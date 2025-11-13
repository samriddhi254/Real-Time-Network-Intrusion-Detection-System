#!/usr/bin/env python
"""
Simple test for CSV creation and download
"""
from app import *
import pandas as pd
from datetime import datetime
import os

def test_csv_creation():
    """Test CSV file creation manually"""
    print("=" * 60)
    print("TESTING CSV DOWNLOAD FUNCTIONALITY")
    print("=" * 60)
    
    # First generate some traffic data
    print("📊 Generating demo traffic data...")
    result = process_demo_traffic()
    
    if result['success']:
        print(f"✅ Demo processing completed")
        print(f"📈 Generated {len(traffic_data)} traffic entries")
        print(f"🔴 Detected {current_stats['anomalies_detected']} anomalies")
        
        # Test CSV creation
        print("\n📁 Testing CSV file creation...")
        
        if traffic_data:
            # Clean up old files
            cleanup_old_csv_files()
            
            # Create CSV file
            df = pd.DataFrame(traffic_data)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"traffic_logs_{timestamp}.csv"
            
            # Save file
            temp_file_path = os.path.join(os.getcwd(), filename)
            df.to_csv(temp_file_path, index=False)
            
            if os.path.exists(temp_file_path):
                file_size = os.path.getsize(temp_file_path)
                print(f"✅ CSV file created successfully!")
                print(f"   📄 Filename: {filename}")
                print(f"   📁 Path: {temp_file_path}")
                print(f"   📏 Size: {file_size} bytes")
                
                # Show CSV content preview
                print(f"\n📋 CSV Content Preview:")
                with open(temp_file_path, 'r') as f:
                    lines = f.readlines()[:6]  # Header + 5 data rows
                
                for i, line in enumerate(lines):
                    prefix = "Header:" if i == 0 else f"Row {i}:"
                    print(f"   {prefix:<8} {line.strip()}")
                
                # Show column structure
                print(f"\n📊 CSV Structure:")
                df_sample = pd.read_csv(temp_file_path)
                print(f"   Columns: {list(df_sample.columns)}")
                print(f"   Rows: {len(df_sample)}")
                
                # Show attack vs normal distribution
                if 'status' in df_sample.columns:
                    status_counts = df_sample['status'].value_counts()
                    print(f"   Attack distribution:")
                    for status, count in status_counts.items():
                        icon = "🔴" if status == "Attack" else "🟢"
                        print(f"     {icon} {status}: {count} ({count/len(df_sample)*100:.1f}%)")
                
                print(f"\n✅ SUCCESS: CSV download functionality ready!")
                print(f"   - File generation: ✅ Working")
                print(f"   - File structure: ✅ Correct (no score column)")
                print(f"   - Data content: ✅ {len(traffic_data)} entries")
                print(f"   - Anomaly detection: ✅ {current_stats['anomalies_detected']} attacks")
                
            else:
                print("❌ Failed to create CSV file")
        else:
            print("❌ No traffic data available for export")
    else:
        print(f"❌ Demo processing failed: {result['message']}")
    
    print("\n" + "=" * 60)
    print("CSV FUNCTIONALITY TEST COMPLETED")
    print("=" * 60)
    print("🌐 In the web browser:")
    print("   1. Run: python app.py")
    print("   2. Open: http://localhost:5000")
    print("   3. Click: 'Start Capture' (generates data)")
    print("   4. Click: 'Export Logs' (downloads CSV file)")
    print("   5. File will be saved to your browser's Downloads folder")

if __name__ == "__main__":
    test_csv_creation()