#!/bin/bash
# KMIM v2.0 Demo Script
# Demonstrates all major functionality

echo "🚀 KMIM v2.0 - Advanced Kernel Module Integrity Monitor Demo"
echo "============================================================"

# Change to KMIM directory
cd /home/nimisha/Files/Courses/CNS_LAB/LAB07

echo ""
echo "📁 Setting up directories..."
sudo mkdir -p /etc/kmim /var/log/kmim
sudo chmod 755 /etc/kmim /var/log/kmim
echo "✅ Directories created: /etc/kmim, /var/log/kmim"

echo ""
echo "📊 Creating baseline..."
sudo python -m cli.kmim baseline /etc/kmim/demo_baseline.json
echo "✅ Baseline created"

echo ""
echo "🔍 Performing integrity scan..."
sudo python -m cli.kmim scan /etc/kmim/demo_baseline.json
echo "✅ Scan completed"

echo ""
echo "🎭 Simulating attack scenarios..."
echo "--- Syscall Hook Attack ---"
sudo python -m cli.kmim simulate hook
echo ""
echo "--- Hidden Module Attack ---"
sudo python -m cli.kmim simulate hidden
echo ""
echo "--- Module Tampering Attack ---"
sudo python -m cli.kmim simulate tamper
echo "✅ Attack simulations completed"

echo ""
echo "📄 Generating security report..."
sudo python -m cli.kmim scan /etc/kmim/demo_baseline.json > /dev/null 2>&1
sudo python -m cli.kmim report --format json --output /tmp/kmim_demo_report.json
echo "✅ Report generated: /tmp/kmim_demo_report.json"

echo ""
echo "📋 Displaying module information..."
sudo python -m cli.kmim show nvidia
echo "✅ Module details displayed"

echo ""
echo "🔧 Displaying syscall addresses (first 10)..."
sudo python -m cli.kmim syscalls --limit 10
echo "✅ Syscall information displayed"

echo ""
echo "📝 Displaying recent logs..."
sudo python -m cli.kmim logs --count 5
echo "✅ Log entries displayed"

echo ""
echo "🔐 Verifying log integrity..."
sudo python -m cli.kmim logs --verify
echo "✅ Log integrity verified"

echo ""
echo "🏁 Demo completed successfully!"
echo "==============================================="
echo "📂 Files created:"
echo "   - /etc/kmim/demo_baseline.json (baseline)"
echo "   - /var/log/kmim/kmim.log (tamper-evident logs)"
echo "   - /tmp/kmim_demo_report.json (security report)"
echo ""
echo "🎯 Next steps:"
echo "   - Deploy as systemd service: sudo cp kmim.service /etc/systemd/system/"
echo "   - Start continuous monitoring: sudo python -m cli.kmim monitor /etc/kmim/demo_baseline.json"
echo "   - Integrate with SIEM using JSON reports"
echo ""
echo "📖 Documentation: man kmim | README.md | docs/REPORT.md"
