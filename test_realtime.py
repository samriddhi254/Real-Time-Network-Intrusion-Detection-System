#!/usr/bin/env python
"""
Test real-time functionality
"""
import requests
import time
import json

def test_realtime_capture():
    """Test start/stop capture functionality"""
    base_url = "http://localhost:5000"
    
    print("=" * 60)
    print("TESTING REAL-TIME CAPTURE FUNCTIONALITY")
    print("=" * 60)
    print("NOTE: Start the Flask app with 'python app.py' first!")
    
    try:
        # Check if server is running
        response = requests.get(f"{base_url}/get_stats", timeout=5)
        print("✅ Flask server is running")
    except:
        print("❌ Flask server is not running. Start it with: python app.py")
        return
    
    # Test demo mode
    print("\n🔍 Testing Demo Mode...")
    
    # Start demo capture
    start_data = {"interface": "Demo Traffic (pcap)"}
    response = requests.post(f"{base_url}/start_capture", 
                           json=start_data, 
                           headers={'Content-Type': 'application/json'})
    
    if response.status_code == 200:
        result = response.json()
        print(f"Start capture result: {result['message']}")
        
        # Wait a moment and check stats
        time.sleep(2)
        
        stats_response = requests.get(f"{base_url}/get_stats")
        stats = stats_response.json()
        print(f"\n📊 Statistics after demo processing:")
        print(f"  Packets analyzed: {stats['packets_analyzed']}")
        print(f"  Flows processed: {stats['flows_processed']}")
        print(f"  Anomalies detected: {stats['anomalies_detected']}")
        
        # Get traffic data
        traffic_response = requests.get(f"{base_url}/get_traffic")
        traffic_data = traffic_response.json()
        print(f"  Traffic entries: {len(traffic_data)}")
        
        if len(traffic_data) > 0:
            print(f"\n🚦 Sample traffic detection:")
            for i, entry in enumerate(traffic_data[:3]):
                status_icon = "🔴" if entry['status'] == 'Attack' else "🟢"
                print(f"  {i+1}. {status_icon} {entry['src_ip']} → {entry['dst_ip']} "
                      f"[{entry['protocol']}] Score: {entry['score']} "
                      f"Severity: {entry['severity']}% Status: {entry['status']}")
            
            attacks = sum(1 for entry in traffic_data if entry['status'] == 'Attack')
            normal = sum(1 for entry in traffic_data if entry['status'] == 'Normal')
            
            print(f"\n📈 Detection Summary:")
            print(f"  🔴 Attacks: {attacks} ({attacks/len(traffic_data)*100:.1f}%)")
            print(f"  🟢 Normal: {normal} ({normal/len(traffic_data)*100:.1f}%)")
            
            if attacks > 5:  # More than 5 attacks detected
                print(f"\n✅ REAL-TIME ANOMALY DETECTION IS WORKING!")
                print("The system now detects multiple suspicious network flows.")
            else:
                print(f"\n⚠️ Only {attacks} anomalies detected. Expected more for demo data.")
        
        # Test stop functionality
        print(f"\n⏹️ Testing stop capture...")
        stop_response = requests.post(f"{base_url}/stop_capture", 
                                    headers={'Content-Type': 'application/json'})
        if stop_response.status_code == 200:
            result = stop_response.json()
            print(f"Stop result: {result['message']}")
        
    print("\n" + "=" * 60)
    print("REAL-TIME TEST COMPLETED")
    print("=" * 60)
    print("🌐 Open http://localhost:5000 in your browser to see the live dashboard!")

if __name__ == "__main__":
    test_realtime_capture()