#!/usr/bin/env python3
"""
Setup script for Ollama - Free Local AI
"""

import subprocess
import sys
import os

def check_ollama_installed():
    """Check if Ollama is installed"""
    try:
        result = subprocess.run(['ollama', '--version'], 
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except:
        return False

def install_ollama_model():
    """Install Llama 3.2 model for Ollama"""
    print("Installing Llama 3.2 model (this may take a few minutes)...")
    try:
        result = subprocess.run(['ollama', 'pull', 'llama3.2'], 
                              capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print("Model installed successfully!")
            return True
        else:
            print(f"Error installing model: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("Installation timed out. Please run 'ollama pull llama3.2' manually.")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("=== Ollama Setup for Free AI Fix Suggestions ===")
    print()
    
    if not check_ollama_installed():
        print("Ollama is not installed!")
        print()
        print("To install Ollama:")
        print("1. Go to https://ollama.ai")
        print("2. Download and run the installer")
        print("3. Restart your terminal")
        print()
        print("After installation, run this script again.")
        return
    
    print("Ollama is installed! Checking for models...")
    
    # Check if model exists
    try:
        result = subprocess.run(['ollama', 'list'], 
                              capture_output=True, text=True, timeout=10)
        if 'llama3.2' in result.stdout:
            print("Llama 3.2 model is already installed!")
        else:
            print("Installing Llama 3.2 model...")
            if not install_ollama_model():
                return
    except:
        print("Could not check models. Trying to install...")
        install_ollama_model()
    
    print()
    print("=== Testing Ollama ===")
    try:
        result = subprocess.run(['ollama', 'run', 'llama3.2', 'Hello!'], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("Ollama test successful!")
            print("Response:", result.stdout[:100] + "..." if len(result.stdout) > 100 else result.stdout)
        else:
            print("Ollama test failed:", result.stderr)
    except Exception as e:
        print("Error testing Ollama:", e)
    
    print()
    print("=== Next Steps ===")
    print("1. Your security scanner will now use Ollama automatically")
    print("2. Run a scan to see AI-powered fix suggestions")
    print("3. No API keys or payments required!")

if __name__ == "__main__":
    main()
