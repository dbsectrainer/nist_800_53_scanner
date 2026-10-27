import os
import json
import time
from collections import deque
from typing import Any
from collections.abc import Callable
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import zmq  # For distributed computing communication

class DistributedScanner:
    def __init__(self, 
                 max_workers: int = None, 
                 distributed_mode: bool = False,
                 broker_address: str = 'localhost',
                 broker_port: int = 5555):
        """
        Initialize Distributed Scanner
        
        Args:
            max_workers: Maximum number of concurrent workers
            distributed_mode: Enable distributed scanning across multiple machines
            broker_address: Address of the distributed computing broker
            broker_port: Port for broker communication
        """
        self.max_workers = max_workers or (os.cpu_count() or 1)
        self.distributed_mode = distributed_mode
        self.broker_address = broker_address
        self.broker_port = broker_port
        
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Setup logging handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _local_parallel_scan(self, 
                              scan_targets: list[Any], 
                              scan_function: Callable,
                              chunk_size: int = 10) -> list[dict]:
        """
        Perform parallel scanning on local machine
        
        Args:
            scan_targets: List of targets to scan
            scan_function: Function to apply to each target
            chunk_size: Number of targets per worker
        
        Returns:
            List of scan results
        """
        results = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Split targets into chunks for more efficient processing
                chunked_targets = [
                    scan_targets[i:i + chunk_size] 
                    for i in range(0, len(scan_targets), chunk_size)
                ]
                
                futures = [
                    executor.submit(self._process_chunk, chunk, scan_function)
                    for chunk in chunked_targets
                ]
                
                for future in as_completed(futures):
                    try:
                        chunk_results = future.result()
                        results.extend(chunk_results)
                    except Exception as e:
                        self.logger.error(f"Chunk processing error: {e}")
        except Exception as e:
            self.logger.error(f"Local parallel scan error: {e}")
        
        return results

    def _process_chunk(self, 
                        chunk: list[Any], 
                        scan_function: Callable) -> list[dict]:
        """
        Process a chunk of scan targets
        
        Args:
            chunk: List of targets to scan
            scan_function: Scanning function to apply
        
        Returns:
            List of scan results for the chunk
        """
        chunk_results = []
        for target in chunk:
            try:
                result = scan_function(target)
                chunk_results.append(result)
            except Exception as e:
                self.logger.error(f"Error scanning target {target}: {e}")
        
        return chunk_results

    def _setup_distributed_broker(self):
        """
        Setup ZeroMQ broker for distributed scanning
        
        Returns:
            Tuple of (socket, context) for broker management
        """
        context = zmq.Context()
        socket = context.socket(zmq.ROUTER)
        
        try:
            socket.bind(f"tcp://{self.broker_address}:{self.broker_port}")
            self.logger.info(f"Distributed broker listening on {self.broker_address}:{self.broker_port}")
            return socket, context
        except Exception as e:
            self.logger.error(f"Failed to setup broker: {e}")
            context.term()
            raise

    def distributed_scan(self,
                         scan_targets: list[Any],
                         scan_function: Callable,
                         timeout: float = 60.0) -> list[dict]:
        """
        Perform distributed scanning across worker processes connected to the broker

        Targets are handed to idle workers one at a time. The scan ends when every
        target has been answered (result or error) or the timeout elapses, in which
        case the results gathered so far are returned.

        Args:
            scan_targets: List of JSON-serialisable targets to scan
            scan_function: Used only in local mode; workers carry their own function
            timeout: Maximum seconds to wait for the whole scan

        Returns:
            List of scan results (targets whose scan raised are omitted)
        """
        if not self.distributed_mode:
            return self._local_parallel_scan(scan_targets, scan_function)

        broker_socket = None
        context = None
        worker_results: list[dict] = []
        pending = deque(scan_targets)
        workers: dict[bytes, str] = {}

        try:
            broker_socket, context = self._setup_distributed_broker()
            poller = zmq.Poller()
            poller.register(broker_socket, zmq.POLLIN)
            deadline = time.monotonic() + timeout

            while pending or 'busy' in workers.values():
                if time.monotonic() >= deadline:
                    self.logger.warning(
                        f"Distributed scan timed out with {len(pending)} unassigned targets "
                        f"and {list(workers.values()).count('busy')} in flight"
                    )
                    break

                if poller.poll(timeout=100):
                    parts = broker_socket.recv_multipart()
                    worker_id, kind = parts[0], parts[1]

                    if kind == b'ready':
                        workers[worker_id] = 'idle'
                    elif kind == b'result':
                        worker_results.append(json.loads(parts[2].decode()))
                        workers[worker_id] = 'idle'
                    elif kind == b'error':
                        self.logger.error(f"Worker failed to scan target: {parts[2].decode()}")
                        workers[worker_id] = 'idle'

                for worker_id, status in workers.items():
                    if not pending:
                        break
                    if status == 'idle':
                        broker_socket.send_multipart([
                            worker_id, b'work', json.dumps(pending.popleft()).encode()
                        ])
                        workers[worker_id] = 'busy'

            for worker_id in workers:
                broker_socket.send_multipart([worker_id, b'stop'])

            return worker_results

        except Exception as e:
            self.logger.error(f"Distributed scanning error: {e}")
            return []
        finally:
            if broker_socket:
                broker_socket.close(linger=100)
            if context:
                context.term()

    def worker_process(self, scan_function: Callable, idle_timeout: float | None = None):
        """
        Worker process for distributed scanning

        Runs until the broker sends a stop message or, if given, until no message
        arrives for idle_timeout seconds.

        Args:
            scan_function: Function to perform scanning
            idle_timeout: Seconds without a message before the worker exits (None = never)
        """
        context = None
        socket = None

        try:
            context = zmq.Context()
            socket = context.socket(zmq.DEALER)
            socket.connect(f"tcp://{self.broker_address}:{self.broker_port}")
            socket.send_multipart([b'ready'])

            last_message = time.monotonic()
            while True:
                if not socket.poll(timeout=100):
                    if idle_timeout is not None and time.monotonic() - last_message > idle_timeout:
                        break
                    continue

                last_message = time.monotonic()
                message = socket.recv_multipart()

                if message[0] == b'stop':
                    break
                if message[0] != b'work':
                    continue

                target = json.loads(message[1].decode())
                try:
                    result = scan_function(target)
                except Exception as e:
                    self.logger.error(f"Error scanning target {target}: {e}")
                    socket.send_multipart([b'error', f"{target}: {e}".encode()])
                    continue
                socket.send_multipart([b'result', json.dumps(result).encode()])

        except Exception as e:
            self.logger.error(f"Worker error: {e}")

        finally:
            if socket:
                socket.close(linger=100)
            if context:
                context.term()
