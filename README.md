
---

# Stronghold 2 Multiplayer AI Patch

This tool applies a live memory patch to **Stronghold 2 (Steam version 1.5 only)** while the game is running. It modifies specific instructions to re-enable AI opponents in multiplayer matches. Only the player hosting the match needs to run this tool.

This tool was originally created for personal use, but you’re welcome to modify and share it freely. I’ve used it to enjoy multiplayer matches with friends, including games featuring AI opponents in Stronghold 2.

## Requirements

* **Windows**
* **Visual Studio 2022**
* **CMake** (version 3.30+ recommended)
* Administrator rights while running the tool

# Building

## <ins>**1. Downloading the repository:**</ins>

Start by cloning the repository with `git clone https://github.com/Tycjan-Fortuna-IT/Stronghold2-MP-AI-Patch`.

Then navigate into the repository directory.

## <ins>**2. Configuring the project:**</ins>

Open a terminal in the project directory and run:

```bash
cmake -S . -B build -G "Visual Studio 17 2022"
```

## <ins>**3. Building the project:**</ins>
Build in **Release** mode:

```bash
cmake --build build --config Release
```

Executable will be located located in `build/Release/`.

## Usage

1. Launch **Stronghold 2 (Steam version 1.5)**.
2. Stay in the main menu, minimize the game window.
3. Run the compiled executable as **Administrator**.
4. Host a multiplayer game.

---

## Notes
* This patch **does not** modify game files — it only affects the current game session.
* You will need to re-run the tool each time you start the game.
