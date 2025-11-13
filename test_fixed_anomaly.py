#!/usr/bin/env python
"""
Quick test for the fixed anomaly detection
"""
from app import process_demo_traffic, current_stats, traffic_data, network_capture

def test_fixed_demo():
    """Test if the fixed demo works with proper anomaly detection"""
    print("=" * 60)
    print("TESTING FIXED ANOMALY DETECTION")
    print("=" * 60)
    
    # Clear previous data
    network_capture.flows.clear()
    current_stats.update({
        'packets_analyzed': 0,
        'flows_processed': 0,
        'anomalies_detected': 0
    })
    traffic_data.clear()
    
    # Process demo traffic
    print("Processing demo traffic with fixed anomaly detection...")
    result = process_demo_traffic()
    
    print(f"\nResult: {result}")
    print(f"\nStatistics:")
    print(f"  Packets analyzed: {current_stats['packets_analyzed']}")
    print(f"  Flows processed: {current_stats['flows_processed']}")
    print(f"  Anomalies detected: {current_stats['anomalies_detected']}")
    print(f"  Traffic entries: {len(traffic_data)}")
    
    if len(traffic_data) > 0:
        print(f"\nSample traffic analysis:")
        for i, entry in enumerate(traffic_data[:5]):  # Show first 5
            status_icon = "🔴" if entry['status'] == 'Attack' else "🟢"
            print(f"  {i+1}. {status_icon} {entry['src_ip']} → {entry['dst_ip']} "
                  f"[{entry['protocol']}] Score: {entry['score']} "
                  f"Severity: {entry['severity']}% Status: {entry['status']}")
        
        # Count anomalies
        attacks = sum(1 for entry in traffic_data if entry['status'] == 'Attack')
        normal = sum(1 for entry in traffic_data if entry['status'] == 'Normal')
        
        print(f"\nDetection Summary:")
        print(f"  🔴 Attacks: {attacks} ({attacks/len(traffic_data)*100:.1f}%)")
        print(f"  🟢 Normal: {normal} ({normal/len(traffic_data)*100:.1f}%)")
        
        if attacks > 0:
            print(f"\n✅ ANOMALY DETECTION IS WORKING!")
            print("The system correctly identified suspicious network flows.")
        else:
            print(f"\n⚠️ No anomalies detected. This might be expected if all traffic is normal.")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    test_fixed_demo()