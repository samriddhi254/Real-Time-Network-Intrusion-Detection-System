#!/usr/bin/env python
"""
Test CSV download functionality
"""
import requests
import os
import time

def test_csv_download():
    """Test the CSV download functionality"""
    base_url = "http://localhost:5000"
    
    print("=" * 60)
    print("TESTING CSV DOWNLOAD FUNCTIONALITY")
    print("=" * 60)
    print("NOTE: Make sure Flask app is running with 'python app.py'")
    
    try:
        # Check if server is running
        response = requests.get(f"{base_url}/get_stats", timeout=5)
        print("✅ Flask server is running")
    except:
        print("❌ Flask server is not running. Start it with: python app.py")
        return
    
    try:
        # First, start demo processing to get some data
        print("\n📊 Starting demo processing to generate data...")
        start_data = {"interface": "Demo Traffic (pcap)"}
        response = requests.post(f"{base_url}/start_capture", 
                               json=start_data, 
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            print("✅ Demo processing started")
            time.sleep(3)  # Wait for processing to complete
            
            # Check stats
            stats_response = requests.get(f"{base_url}/get_stats")
            stats = stats_response.json()
            print(f"📈 Data available: {stats['flows_processed']} flows, {stats['anomalies_detected']} anomalies")
            
            # Test export functionality
            print("\n📥 Testing export/download functionality...")
            export_response = requests.post(f"{base_url}/export_logs", 
                                          headers={'Content-Type': 'application/json'})
            
            if export_response.status_code == 200:
                export_result = export_response.json()
                print(f"✅ Export prepared: {export_result['message']}")
                
                if export_result['success']:
                    filename = export_result['filename']
                    download_url = export_result['download_url']
                    
                    print(f"📄 Generated file: {filename}")
                    print(f"🔗 Download URL: {download_url}")
                    
                    # Test the download endpoint
                    download_response = requests.get(f"{base_url}{download_url}")
                    
                    if download_response.status_code == 200:
                        print("✅ Download endpoint working")
                        
                        # Check if file exists on server
                        if os.path.exists(filename):
                            file_size = os.path.getsize(filename)
                            print(f"📁 File created on server: {filename} ({file_size} bytes)")
                            
                            # Show first few lines of the CSV
                            with open(filename, 'r') as f:
                                lines = f.readlines()[:5]  # First 5 lines
                            
                            print(f"\n📋 CSV Content Preview:")
                            for i, line in enumerate(lines):
                                print(f"   {i+1}: {line.strip()}")
                            
                            print(f"\n✅ SUCCESS: CSV download functionality is working!")
                            print(f"   - File generated: {filename}")
                            print(f"   - Download URL works: {download_url}")
                            print(f"   - File size: {file_size} bytes")
                            print(f"   - Contains: {len(lines)} lines (showing 5)")
                            
                        else:
                            print("❌ File not found on server")
                    else:
                        print(f"❌ Download failed with status: {download_response.status_code}")
                else:
                    print(f"❌ Export failed: {export_result['message']}")
            else:
                print(f"❌ Export request failed with status: {export_response.status_code}")
        else:
            print("❌ Failed to start demo processing")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    print("\n" + "=" * 60)
    print("CSV DOWNLOAD TEST COMPLETED")
    print("=" * 60)
    print("💡 In the web interface:")
    print("   1. Click 'Start Capture' to generate data")
    print("   2. Click 'Export Logs' to download CSV file")
    print("   3. File will be automatically downloaded to your browser's download folder")

if __name__ == "__main__":
    test_csv_download()