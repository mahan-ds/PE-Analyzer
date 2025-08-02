# 🧠 PE-Analyzer

A lightweight C++ tool to inspect PE (Portable Executable) files such as `.exe` or `.dll`.  
You can extract embedded URLs, search for specific functions, and perform basic static analysis.

---

## 🛠 Features

- ✅ Extracts URLs from `.exe`/`.dll` files
- 🔍 Locates exported or imported functions (e.g., `CreateFileA`, `VirtualAlloc`)
- 📂 Command-line interface (CLI)

---

## 🧰 Requirements

- **CMake** (>= 3.15)
- **C++ Compiler**
  - Windows: MSVC / MinGW
  - Linux/macOS: GCC or Clang
- **Git** (optional)

---

## ⚙️ Build Instructions (Windows)

Open a terminal (`cmd`, `PowerShell`, or Git Bash):

```bash
git clone https://github.com/mahan-ds/PE-Analyzer.git
cd PE-Analyzer
mkdir build
cd build
cmake ..
cmake --build .
```

This will create the executable `pe_checker.exe` inside:

```
build/Debug/
```

---

## 🚀 How to Run

You must **navigate into the build output folder**, e.g.:

```bash
cd build/Debug
```

### ✅ Extract URLs from a PE file:

```bash
pe_checker.exe --file C:\Windows\System32\kernel32.dll -U
```

> `-U` will extract and list all found URLs.

### 🔎 Check for specific function names:

```bash
pe_checker.exe --file C:\Windows\System32\kernel32.dll -f CreateFileA -f CreateFileW
```

> `-f` allows checking if a specific function is present (imported/exported).  
> You can pass multiple `-f` flags.

---

## 🧪 Example Output

```
CreateFileA: found
CreateImage: not found
```

---

## 📂 Folder Structure

```
PE-Analyzer/
├── src/                # Source code (main.cpp, utils)
├── CMakeLists.txt      # Build config
├── Resault image/      # Screenshots or output examples
├── LICENSE
├── README.md
└── build/              # Created during build
    └── Debug/
        └── pe_checker.exe
```

---

## 📄 License

This project is licensed under the MIT License.  
See the [LICENSE](./LICENSE) file for details.

