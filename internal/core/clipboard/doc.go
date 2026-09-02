// Package clipboard holds the clipboard exchange rules: splitting and
// rejoining oversized content across the 4-byte part header, and the inbound
// disposition covering automatic apply, the single pending-entry lifecycle,
// digest-based echo suppression, and rejection of oversized or invalid content.
//
// Pure logic only. The system clipboard itself is reached through the
// ClipboardPort adapter in internal/platform/clip; this package must not
// import net, os, or any socket API.
package clipboard
