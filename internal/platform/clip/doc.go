// Package clip is the system clipboard adapter. It implements the
// ClipboardPort read and write operations by shelling out with os/exec to the
// tool each host already ships: pbpaste and pbcopy on macOS, Get-Clipboard and
// clip.exe on Windows, wl-paste and wl-copy on Linux with an xclip fallback.
//
// When no tool is present, clipboard operations report unsupported rather than
// failing the whole node.
package clip
