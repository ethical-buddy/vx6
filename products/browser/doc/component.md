# components

this document lists the main ui and helper elements used in the browser window implementation and explains what each one does.

## browserwindow

this is the main window class that owns the web profile, tabs, toolbar, and side panel. it wires all ui pieces together, registers backend callbacks, and handles navigation and node actions.

## vx6tabwidget

this is a small wrapper around qtabwidget that exposes a helper to install a custom tab bar. it keeps the normal qtabwidget behavior but lets us swap in the painted close button tab bar.

## vx6tabbar

this custom tab bar draws its own close button. it extends qtabbar and overrides paint and mouse handling so the close x is rendered manually and can be clicked. it keeps a hover state, paints a hover background, and emits tab close requests when the user clicks inside the close area.

## vx6requestinterceptor

this is a request filter for the web engine. it blocks file, ftp, and javascript schemes so the browser only loads the intended http and vx6 content.

## kbase style string

this is the global font style applied to the window. it keeps the app typography consistent across tabs, toolbar, and dock.

## main tab area

the tab widget is created in buildui. it sets document mode, tab closable, and movable behavior. the stylesheet defines the tab bar colors, hover state, and selected state, and hides the native close button so only the custom one is visible.

## navigation toolbar

the toolbar is created in buildtoolbar. it contains the back, forward, reload, and home actions, the address bar, and the right side utility buttons. the toolbar stylesheet controls the background, button hover states, and address bar styling.

## address bar

the address bar is a qlineedit that accepts vx6, http, https, and local addresses. it includes a clear button and uses extra padding so the clear icon does not overlap the text.

## right side toolbar buttons

these are small utility buttons for bookmark, new tab, and toggling the side panel. they are styled as minimal glyph buttons with hover states.

## side panel dock

the dock widget is created in builddock. it hosts quick controls for node actions, a shortcut list, and an activity log. it uses a custom close icon and matches the tab close styling for hover.

## node control buttons

the node buttons are created with makesidebtn, a helper that applies a consistent style. start, stop, and reload are grouped at the top of the dock, with status and permission shortcuts below.

## quick nav list

this is a list widget that links to common vx6 pages. it uses a compact list style with hover and selected states.

## activity log

this is a read only text view that shows runtime and navigation activity. it uses a monospace font and a thin scroll bar.

## backend callbacks

registerbrowsercallbacks connects the backend log signal to the ui log view so runtime messages appear in the activity section.

## permission prompt

maybeshowpermissionprompt handles first run permissions. it shows a modal prompt and can navigate to the permissions page.

## tab helpers

createtab creates the web engine view and page, connects the url and title updates back to the tab and address bar, and logs page load results.

## navigation helpers

openhome, newtab, and navigateto manage address resolution and loading. normalizetarget formats raw input into a valid vx6 or http url.

## node operations

startnode, stopnode, and reloadnode call into the backend and refresh the status page when needed.

## bookmarks

bookmarkcurrent stores the current url in settings so it can be referenced later.

## logging

appendlog writes a line into the activity view so user actions and backend events are visible.
