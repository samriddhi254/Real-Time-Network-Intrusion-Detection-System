#!/usr/bin/env python
"""
Test the start/stop functionality
"""
import time
from app import *

def test_start_stop_demo():
    """Test that start/stop works and doesn't process all packets at once"""
    print("=" * 60)
    print("TESTING START/STOP CONTROL")
    print("=" * 60)
    
    # Reset everything
    global capture_active, current_stats, traffic_data
    capture_active = False
    current_stats.update({
        'packets_analyzed': 0,
        'flows_processed': 0,
        'anomalies_detected': 0
    })
    traffic_data.clear()
    network_capture.flows.clear()
    
    print("✅ Starting demo processing in background...")
    
    # Start demo processing in a thread (simulating user clicking start)
    capture_active = True
    import threading
    demo_thread = threading.Thread(target=process_demo_traffic_threaded)
    demo_thread.start()
    
    # Let it run for a bit to process some packets
    time.sleep(1.0)  # Let some packets process
    packets_mid = current_stats['packets_analyzed']
    print(f"📊 After 1 second - Packets: {packets_mid}, Anomalies: {current_stats['anomalies_detected']}")
    
    # Stop it (simulating user clicking stop)
    print("🛑 Stopping demo processing...")
    capture_active = False
    
    # Wait for thread to finish
    demo_thread.join()
    
    print(f"📊 Final stats - Packets: {current_stats['packets_analyzed']}, Flows: {current_stats['flows_processed']}, Anomalies: {current_stats['anomalies_detected']}")
    
    if current_stats['packets_analyzed'] < 100:
        print("✅ SUCCESS: Packets were not all processed at once!")
        print(f"   Only {current_stats['packets_analyzed']} packets processed before stop.")
    else:
        print("❌ ISSUE: All packets were processed despite stop command.")
    
    if len(traffic_data) > 0:
        print(f"📈 Traffic table has {len(traffic_data)} entries")
        attacks = sum(1 for entry in traffic_data if entry['status'] == 'Attack')
        print(f"🔴 Detected {attacks} attacks")
    
    print("\n" + "=" * 60)
    print("START/STOP TEST COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    test_start_stop_demo()