use crate::sync::{Condvar, Mutex, MutexBlocking, MutexSpin, Semaphore};
use crate::syscall::sys_gettid;
use crate::task::{block_current_and_run_next, current_process, current_task};
use crate::timer::{add_timer, get_time_ms};
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub fn sys_sleep(ms: usize) -> isize {
    let expire_ms = get_time_ms() + ms;
    let task = current_task().unwrap();
    add_timer(expire_ms, task);
    block_current_and_run_next();
    0
}

// LAB5 HINT: you might need to maintain data structures used for deadlock detection
// during sys_mutex_* and sys_semaphore_* syscalls
pub fn sys_mutex_create(blocking: bool) -> isize {
    let process = current_process();
    let mutex: Option<Arc<dyn Mutex>> = if !blocking {
        Some(Arc::new(MutexSpin::new()))
    } else {
        Some(Arc::new(MutexBlocking::new()))
    };
    let mut process_inner = process.inner_exclusive_access();
    if let Some(id) = process_inner
        .mutex_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.mutex_list[id] = mutex;
        id as isize
    } else {
        process_inner.mutex_list.push(mutex);
        process_inner.mutex_alloc.push(None);
        process_inner.mutex_list.len() as isize - 1
    }
}

// LAB5 HINT: Return -0xDEAD if deadlock is detected
pub fn sys_mutex_lock(mutex_id: usize) -> isize {
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    let detect_enabled = process_inner.deadlock_detect;
    let tid = current_task()
        .unwrap()
        .inner_exclusive_access()
        .res
        .as_ref()
        .unwrap()
        .tid;
    process_inner.mutex_request[tid] = Some(mutex_id);

    if detect_enabled {
        let mut visited = BTreeSet::<usize>::new();
        visited.insert(tid);
        let mut mid = mutex_id;
        while let Some(tid2) = process_inner.mutex_alloc[mid] {
            if visited.contains(&tid2) {
                println!(
                    " ----- deadlock! pid: {}, tid: {}, mutex_id: {} ------",
                    process.pid.0, tid, mutex_id
                );
                return -0xDEAD;
            } else {
                visited.insert(tid2);
                if let Some(mid2) = process_inner.mutex_request[tid2] {
                    mid = mid2;
                } else {
                    break;
                }
            }
        }
    }
    drop(process_inner);
    drop(process);
    mutex.lock();
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    process_inner.mutex_alloc[mutex_id] = Some(tid);
    process_inner.mutex_request[tid] = None;
    0
}

pub fn sys_mutex_unlock(mutex_id: usize) -> isize {
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    process_inner.mutex_alloc[mutex_id] = None;
    drop(process_inner);
    drop(process);
    mutex.unlock();
    0
}

pub fn sys_semaphore_create(res_count: usize) -> isize {
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let id = if let Some(id) = process_inner
        .semaphore_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.semaphore_list[id] = Some(Arc::new(Semaphore::new(res_count)));
        process_inner.sem_avail[id] = res_count;
        id
    } else {
        process_inner
            .semaphore_list
            .push(Some(Arc::new(Semaphore::new(res_count))));
        process_inner.sem_avail.push(res_count);
        for alloc in process_inner.sem_alloc.iter_mut() {
            alloc.push(0);
        }
        process_inner.semaphore_list.len() - 1
    };
    id as isize
}

pub fn sys_semaphore_up(sem_id: usize) -> isize {
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let sem = Arc::clone(process_inner.semaphore_list[sem_id].as_ref().unwrap());
    drop(process_inner);
    sem.up();
    0
}

// LAB5 HINT: Return -0xDEAD if deadlock is detected
pub fn sys_semaphore_down(sem_id: usize) -> isize {
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let sem = Arc::clone(process_inner.semaphore_list[sem_id].as_ref().unwrap());
    let tid = sys_gettid() as usize;
    assert!(process_inner.tasks.len() == process_inner.sem_request.len());

    process_inner.sem_request[tid] = Some(sem_id);
    let det = process_inner.deadlock_detect;
    if det {
        // deadlock detection
        // init
        let mut work = process_inner.sem_avail.clone();
        let mut not_finished = BTreeSet::<usize>::new();
        for (tid2, t_alloc) in process_inner.sem_alloc.iter().enumerate() {
            if !t_alloc.is_empty() {
                not_finished.insert(tid2);
            }
        }

        let mut all_released = false;
        let mut all_finished = not_finished.is_empty();
        while !all_finished && !all_released {
            all_released = true;
            let mut finished = Vec::<usize>::new();
            for tid2 in not_finished.iter() {
                // step 2
                if let Some(sid) = process_inner.sem_request[*tid2] {
                    if work[sid] == 0 {
                        continue;
                    }
                }
                all_released = false;
                // step 3
                finished.push(*tid2);
                for (sid, num) in process_inner.sem_alloc[*tid2].iter().enumerate() {
                    work[sid] += num;
                }
            }
            for tid2 in finished.iter() {
                not_finished.remove(tid2);
            }
            // not_finished = not_finished.difference(&finished).collect();
            all_finished = not_finished.is_empty();
        }

        if !not_finished.is_empty() {
            println!(
                "--- deadlock! pid: {}, tid: {}, sem_id: {}",
                process.pid.0, tid, sem_id
            );
            return -0xDEAD;
        }
    }
    drop(process_inner);
    sem.down();
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    process_inner.sem_request[tid] = None;
    process_inner.sem_avail[sem_id] -= 1;
    process_inner.sem_alloc[tid][sem_id] += 1;
    0
}

pub fn sys_condvar_create(_arg: usize) -> isize {
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let id = if let Some(id) = process_inner
        .condvar_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.condvar_list[id] = Some(Arc::new(Condvar::new()));
        id
    } else {
        process_inner
            .condvar_list
            .push(Some(Arc::new(Condvar::new())));
        process_inner.condvar_list.len() - 1
    };
    id as isize
}

pub fn sys_condvar_signal(condvar_id: usize) -> isize {
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let condvar = Arc::clone(process_inner.condvar_list[condvar_id].as_ref().unwrap());
    drop(process_inner);
    condvar.signal();
    0
}

pub fn sys_condvar_wait(condvar_id: usize, mutex_id: usize) -> isize {
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let condvar = Arc::clone(process_inner.condvar_list[condvar_id].as_ref().unwrap());
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    drop(process_inner);
    condvar.wait(mutex);
    0
}

// LAB5 YOUR JOB: Implement deadlock detection, but might not all in this syscall
pub fn sys_enable_deadlock_detect(enabled: usize) -> isize {
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    match enabled {
        0 => {
            inner.deadlock_detect = false;
            0
        }
        1 => {
            inner.deadlock_detect = true;
            0
        }
        _ => {
            println!("invalid param {} when call enable_deadlock_detect", enabled);
            -1
        }
    }
}
