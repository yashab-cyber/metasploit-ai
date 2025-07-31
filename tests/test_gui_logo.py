#!/usr/bin/env python3
"""
GUI Logo Test Script
Test the logo integration in the GUI interface
"""

import os
import sys
from pathlib import Path

def test_logo_paths():
    """Test if logo files exist in expected locations"""
    print("🖼️  Testing Logo File Locations")
    print("=" * 50)
    
    # Define possible logo paths
    possible_paths = [
        "src/public/Metaspolit-AI.png",
        "src/web/static/images/Metaspolit-AI.png",
        os.path.join("src", "public", "Metaspolit-AI.png"),
        os.path.join("src", "web", "static", "images", "Metaspolit-AI.png")
    ]
    
    found_logos = []
    
    for path in possible_paths:
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"✅ Found: {path} ({size:,} bytes)")
            found_logos.append(path)
        else:
            print(f"❌ Missing: {path}")
    
    print(f"\n📊 Summary: {len(found_logos)}/{len(possible_paths)} logo files found")
    
    if found_logos:
        print(f"🎯 Primary logo: {found_logos[0]}")
        return found_logos[0]
    else:
        print("⚠️  No logo files found!")
        return None

def test_gui_dependencies():
    """Test if GUI dependencies are available"""
    print("\n🔧 Testing GUI Dependencies")
    print("=" * 50)
    
    dependencies = {
        'tkinter': 'Built-in Python GUI library',
        'customtkinter': 'Modern GUI framework',
        'PIL': 'Python Imaging Library (Pillow)'
    }
    
    available = []
    missing = []
    
    for dep, description in dependencies.items():
        try:
            if dep == 'tkinter':
                import tkinter
            elif dep == 'customtkinter':
                import customtkinter
            elif dep == 'PIL':
                from PIL import Image, ImageTk
            
            print(f"✅ {dep}: {description}")
            available.append(dep)
        except ImportError:
            print(f"❌ {dep}: {description} - NOT INSTALLED")
            missing.append(dep)
    
    print(f"\n📊 Dependencies: {len(available)}/{len(dependencies)} available")
    
    if missing:
        print(f"\n💡 To install missing dependencies:")
        if 'customtkinter' in missing:
            print("   pip install customtkinter")
        if 'PIL' in missing:
            print("   pip install pillow")
    
    return len(missing) == 0

def create_simple_gui_test():
    """Create a simple GUI test with logo"""
    print("\n🖥️  Creating Simple GUI Test")
    print("=" * 50)
    
    try:
        import tkinter as tk
        from PIL import Image, ImageTk
        
        # Find logo
        logo_path = test_logo_paths()
        if not logo_path:
            print("❌ Cannot create GUI test without logo")
            return False
        
        # Create simple window
        root = tk.Tk()
        root.title("Metasploit-AI Logo Test")
        root.geometry("400x300")
        root.configure(bg='#2b2b2b')
        
        # Load and display logo
        try:
            logo_image = Image.open(logo_path)
            logo_image = logo_image.resize((100, 100), Image.Resampling.LANCZOS)
            logo_photo = ImageTk.PhotoImage(logo_image)
            
            # Create logo label
            logo_label = tk.Label(
                root,
                image=logo_photo,
                bg='#2b2b2b'
            )
            logo_label.pack(pady=20)
            
            # Create title
            title_label = tk.Label(
                root,
                text="Metasploit-AI Framework",
                font=("Arial", 16, "bold"),
                fg='white',
                bg='#2b2b2b'
            )
            title_label.pack(pady=10)
            
            # Create subtitle
            subtitle_label = tk.Label(
                root,
                text="Logo Integration Test",
                font=("Arial", 12),
                fg='gray',
                bg='#2b2b2b'
            )
            subtitle_label.pack()
            
            # Create close button
            close_button = tk.Button(
                root,
                text="Close Test",
                command=root.quit,
                bg='#1f6aa5',
                fg='white',
                font=("Arial", 10)
            )
            close_button.pack(pady=20)
            
            print("✅ Simple GUI test window created")
            print("🖼️  Logo loaded and displayed successfully")
            print("👆 Click 'Close Test' to exit")
            
            # Start GUI (comment out for automated testing)
            # root.mainloop()
            
            # Cleanup for automated testing
            root.destroy()
            return True
            
        except Exception as e:
            print(f"❌ Error loading logo: {e}")
            root.destroy()
            return False
            
    except ImportError as e:
        print(f"❌ GUI dependencies not available: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 Metasploit-AI GUI Logo Integration Test")
    print("=" * 60)
    
    # Test logo files
    logo_found = test_logo_paths() is not None
    
    # Test dependencies
    deps_available = test_gui_dependencies()
    
    # Test simple GUI
    gui_test_passed = False
    if logo_found and deps_available:
        gui_test_passed = create_simple_gui_test()
    
    # Summary
    print(f"\n📋 Test Results Summary")
    print("=" * 50)
    print(f"Logo Files: {'✅ FOUND' if logo_found else '❌ MISSING'}")
    print(f"Dependencies: {'✅ AVAILABLE' if deps_available else '❌ MISSING'}")
    print(f"GUI Test: {'✅ PASSED' if gui_test_passed else '❌ FAILED'}")
    
    if logo_found and deps_available and gui_test_passed:
        print(f"\n🎉 All tests passed! GUI with logo is ready.")
        print(f"🚀 Run: python app.py --mode gui")
    else:
        print(f"\n⚠️  Some tests failed. Check the issues above.")
        if not deps_available:
            print(f"💡 Install dependencies: pip install customtkinter pillow")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
