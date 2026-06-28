import os
import time
import queue
import threading
from scapy.all import sniff, IP, TCP, UDP
import sniffer
from logger import log_incident

# Thread-safe First-In, First-Out (FIFO) pipeline channel
packet_fifo_queue = queue.Queue(maxsize=5000)
stop_signal = threading.Event()

def packet_producer_loop(packet_count):
    """
    Producer Thread: Dedicated solely to wire interception.
    Pushes raw packet frames onto the queue instantly without processing.
    """
    log_incident("INFO", "[PRODUCER] Thread launched. Capturing raw socket packets...")
    
    def enqueue_packet(packet):
        try:
            # block=False prevents blocking if the queue capacity fills completely
            packet_fifo_queue.put(packet, block=False)
        except queue.Full:
            pass # Drop packet safely if buffer overflows to save system resource allocation

    # Sniff traffic and feed the enqueue callback handler
    sniff(prn=enqueue_packet, count=packet_count, store=0)
    log_incident("INFO", "[PRODUCER] Sniffing window capture reached targets.")

def packet_consumer_loop():
    """
    Consumer Thread: Processes packet data asynchronously.
    Pulls packets from the queue and runs them through the ML feature extraction pipeline.
    """
    log_incident("INFO", "[CONSUMER] Thread launched. Standby for asynchronous ML evaluation...")
    
    while not stop_signal.is_set() or not packet_fifo_queue.empty():
        try:
            # Timeout ensures thread checks the stop signal periodically even if the queue is empty
            packet = packet_fifo_queue.get(timeout=1.0)
            
            # Delegate back to our engineered sniffer engine to assemble flows and run inference
            sniffer.process_packet(packet)
            
            # Mark the item as processed in the queue tracker
            packet_fifo_queue.task_done()
            
        except queue.Empty:
            continue
            
    log_incident("INFO", "[CONSUMER] Asynchronous queue processing engine safely wound down.")

def run_multithreaded_capture(packet_count=200):
    # Ensure our sniffer model components are fully trained and loaded before launch
    if sniffer.trained_model is None:
        sniffer.train_and_initialize_live_model()
        
    stop_signal.clear()
    
    # Declare explicit worker threads
    producer_worker = threading.Thread(target=packet_producer_loop, args=(packet_count,))
    consumer_worker = threading.Thread(target=packet_consumer_loop)
    
    # Start executing concurrently
    producer_worker.start()
    consumer_worker.start()
    
    # Wait for the producer thread to finish capturing its packet pool
    producer_worker.join()
    
    # Allow the consumer a brief moment to empty any remaining queue items, then shut down cleanly
    time.sleep(2)
    stop_signal.set()
    consumer_worker.join()
    
    log_incident("INFO", "NetPulse Multi-threaded operations successfully completed.")

if __name__ == "__main__":
    run_multithreaded_capture(packet_count=100)