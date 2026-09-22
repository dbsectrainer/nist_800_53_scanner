import os
import json
import time
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
                         scan_function: Callable) -> list[dict]:
        """
        Perform distributed scanning across multiple machines
        
        Args:
            scan_targets: List of targets to scan
            scan_function: Function to apply to each target
        
        Returns:
            List of scan results
        """
        if not self.distributed_mode:
            return self._local_parallel_scan(scan_targets, scan_function)
        
        broker_socket = None
        context = None
        worker_results = []
        
        try:
            broker_socket, context = self._setup_distributed_broker()
            
            # Track worker status
            workers = {}
            
            while scan_targets or workers:
                try:
                    # Check for worker messages with timeout
                    worker_id, message = broker_socket.recv_multipart(zmq.NOBLOCK)
                    
                    # Process worker message
                    if message[0] == b'ready':
                        # Worker is ready for work
                        workers[worker_id] = 'idle'
                    
                    elif message[0] == b'result':
                        # Worker completed a scan
                        result = json.loads(message[1].decode())
                        worker_results.append(result)
                        workers[worker_id] = 'idle'
                
                except zmq.ZMQError as zmq_err:
                    # No message available, continue processing
                    if zmq_err.errno != zmq.EAGAIN:
                        raise
                
                # Assign work to idle workers
                if scan_targets and 'idle' in workers.values():
                    target = scan_targets.pop(0)
                    
                    # Find an idle worker
                    idle_worker = next(
                        worker for worker, status in workers.items() 
                        if status == 'idle'
                    )
                    
                    # Send work to worker
                    broker_socket.send_multipart([
                        idle_worker, 
                        b'work', 
                        json.dumps(target).encode()
                    ])
                    workers[idle_worker] = 'busy'
            
            return worker_results
        
        except Exception as e:
            self.logger.error(f"Distributed scanning error: {e}")
            return []
        finally:
            # Cleanup
            if broker_socket:
                broker_socket.close()
            if context:
                context.term()

    def worker_process(self, scan_function: Callable):
        """
        Worker process for distributed scanning
        
        Args:
            scan_function: Function to perform scanning
        """
        context = None
        socket = None
        
        try:
            context = zmq.Context()
            socket = context.socket(zmq.DEALER)
            socket.connect(f"tcp://{self.broker_address}:{self.broker_port}")
            
            # Signal readiness
            socket.send_multipart([b'ready'])
            
            while True:
                try:
                    # Wait for work with timeout
                    message = socket.recv_multipart(zmq.NOBLOCK)
                    
                    if message[0] == b'work':
                        # Perform scan
                        target = json.loads(message[1].decode())
                        result = scan_function(target)
                        
                        # Send result back
                        socket.send_multipart([
                            b'result', 
                            json.dumps(result).encode()
                        ])
                
                except zmq.ZMQError as zmq_err:
                    # No message available, continue
                    if zmq_err.errno != zmq.EAGAIN:
                        raise
                    time.sleep(0.1)  # Prevent tight loop
                
                except Exception as e:
                    self.logger.error(f"Worker processing error: {e}")
                    break
        
        except Exception as e:
            self.logger.error(f"Worker initialization error: {e}")
        
        finally:
            # Cleanup resources
            if socket:
                socket.close()
            if context:
                context.term()
