import subprocess
import sys
import os

def run_command(command, description):
    print(f"\n▶️ {description}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"❌ Failed: {description}")
        sys.exit(1)
    print(f"✅ Success: {description}")

def main():
    # Step 1: Generate random logs
    run_command("python generate_logs.py", "Generating random auth.log and access.log")
    
    # Step 2: Run the demo script (threat detection test)
    run_command("python demo.py", "Running Mini-SIEM demo analysis")
    
    # Step 3: Launch Streamlit dashboard (this will block until stopped)
    print("\n🚀 Launching Mini-SIEM dashboard...")
    os.execvp(sys.executable, [sys.executable, "-m", "streamlit", "run", "siem_dashboard.py"])

if __name__ == "__main__":
    main()
