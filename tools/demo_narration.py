"""What the voice says at each step of tools/demo.py (key = the step's title). Lively, one idea per step."""

INTRO = "intro"
OUTRO = "outro"

NARRATION: dict[str, str] = {
    INTRO: "Hi! This is LogLens: a fast log viewer and analyzer for Windows, with a built in knowledge base and an "
    "optional AI assistant that can run entirely on your own computer. Let's take a tour of every feature, live.",
    "Welcome page with recent files": "Everything starts on the welcome page, with your recent files one click away.",
    "Switch theme: dark": "It looks great in dark mode...",
    "Switch theme: light": "...and in light mode. Or follow the system theme automatically.",
    "Open a log: format detected, levels and timeline strip": "Open any log, even multi gigabyte files, and LogLens "
    "detects the format on its own. Look at the colored levels and the timeline strip above the text.",
    "Search for 'payment' (live highlight of matches)": "Type in the search box and every match lights up instantly.",
    "Jump to next match": "Jump to the next match...",
    "Jump to previous match": "...or back to the previous one.",
    "Find all matches as results list": "Or list all the matches at once.",
    "Filter by level: warnings and errors only": "Filter by level, to see only warnings and errors. Noise gone!",
    "Next issue (error/warning navigation)": "Then hop from problem to problem with next issue...",
    "Previous issue": "...and previous issue.",
    "Pin filters as chips: must match / must not match": "Pin filters as chips. This one says the line must "
    "contain CacheManager, and this one says it must not contain miss. Combine as many as you like.",
    "Show 2 context lines around each match": "Need the story around a match? Add context lines before and after.",
    "Clear filters": "One click clears everything.",
    "Bookmark a line": "Bookmark the lines that matter...",
    "Next bookmark": "...and jump between them later.",
    "Go to line…": "Go to any line number, like line one hundred and twenty...",
    "Go to time…": "...or go straight to a point in time.",
    "Time range filter…": "Limit the view to a time range, from this moment to that one. Watch the lines narrow down to just that window.",
    "Clock / timezone settings…": "Logs from different servers? Fix the clock and timezone right here.",
    "Word wrap on": "Turn on word wrap for long lines...",
    "Word wrap off": "...and off again.",
    "Hide / show the Inspector": "The inspector panel decodes details on the right. Hide it if you need room...",
    "Hide / show the timeline strip": "...and the same for the timeline strip.",
    "Columns view: parsed fields as a table": "Columns view turns any log into a table of parsed fields. "
    "Sortable, readable, lovely.",
    "Back to plain text view": "And back to plain text whenever you like.",
    "Zoom in / out": "Zoom the text in and out.",
    "Mask secrets toggle": "Here is a log full of secrets: a password, a token, a cloud key. Switch on mask secrets, and look, "
    "they are all hidden. Safe to share your screen.",
    "Encoding menu: reopen as another encoding": "Strange characters? Reopen the file in another encoding.",
    "Highlighters dialog (colour rules)": "Highlighters color lines with your own rules. I add one in red for timeouts and failures, and it applies right away.",
    "Open a JSON-lines log: Inspector decodes the payload": "Structured logs? The inspector decodes Jason payloads, "
    "and also X M L, tokens, U R Ls, S Q L, base sixty four, and stack traces.",
    "Inspector: switch tabs": "Switch between its tabs: details, related events, and the A I answer.",
    "Analyze: message patterns": "Now the analysis tools. Patterns groups thousands of lines into a few message types, "
    "with counts. Instantly you see what your log is really made of.",
    "Analyze: field value counts": "Fields counts the values of any field, like which user or which status appears most.",
    "Analyze: SQL over parsed records": "You can even run S Q L queries over the parsed records!",
    "Analyze: compare (what changed?)": "Compare two logs, or before and after, to see what changed.",
    "Analyze: request / response pairs": "Request and response pairs matches calls with their results, with durations.",
    "Analyze: HTTP request statistics (IIS log)": "And for web server logs, H T T P statistics: top U R Ls, "
    "status codes, slow requests.",
    "Incident report dialog": "Ready to share? Build an incident report in Markdown or H T M L, with your bookmarks "
    "and evidence, and secrets redacted.",
    "Merge open logs into one timeline": "Merge several logs into a single time ordered timeline. "
    "Perfect for tracing a problem across services.",
    "Find in all open logs": "Search across all open logs at once...",
    "Dashboard (live overview)": "...and the live dashboard gives you an overview of everything you are watching.",
    "Knowledge base (offline explanations)": "The knowledge base explains Windows events, error codes, and common "
    "messages, offline. You can add your own entries too, and it learns.",
    "Diagnose this computer": "Diagnose this computer looks for crashes, restarts, failing services, lockouts and "
    "more, right from your Windows event logs.",
    "Windows Event Logs dialog": "Read Windows event logs or E V T X files in the same powerful viewer.",
    "Watch menu: follow files, alerts, services": "The Watch menu follows the newest file in a folder, raises "
    "alerts, and watches Windows services.",
    "AI settings: provider = local Ollama, test connection": "Now the A I assistant. Choose a provider, here a local "
    "model served by Ollama on this very computer, so nothing leaves the machine. Test the connection... connected!",
    "AI: explain the selected line (preview, then local model answer)": "Select a line and ask A I to explain it. "
    "First you get a preview of exactly what will be sent, already redacted, and you can edit it. "
    "Then the local model thinks...",
    "AI: answer shown in the Inspector": "And here is the answer: a summary, severity, probable causes, and next steps. "
    "You can save it to your knowledge base so LogLens learns.",
    "AI: explain the top patterns of the log": "It can even explain the top message patterns of a whole log, "
    "giving you the big picture.",
    "File > Open… (file picker)": "The regular Open dialog works too, and you can drag and drop files onto the window.",
    "Export the filtered lines to CSV": "Export just the filtered lines as text, C S V, or Jason lines. "
    "Secrets stay masked if you want.",
    "Copy lines to the clipboard": "Copy lines straight to the clipboard.",
    "Web search with a cleaned query": "Want to Google an error? LogLens cleans the query first, removing ids and "
    "paths, and lets you pick the parts you want to search.",
    "Teach the knowledge base a new explanation": "Teach the knowledge base. Write what a message means once, "
    "and LogLens explains similar lines forever, offline.",
    "Switch between open tabs": "Work with many logs at once, one tab each.",
    "Open a folder of logs (support bundle)": "Got a whole support bundle, a folder or a zip? Pick the logs you want, "
    "and open or merge them in one go.",
    "Live tail: new lines appear as they are written": "Live tail follows a log while it grows, and handles rotation, "
    "so you watch new lines appear as they are written.",
    "Alert rules for watched logs": "Create alert rules: a match, a burst of errors, or a new kind of message, "
    "with tray notifications.",
    "Watch a folder: always open the newest file": "Watch a folder, and LogLens always opens the newest log file.",
    "Windows Event Logs: read Application and System into a searchable log": "Now Windows event logs. Pick channels "
    "like Application and System, and LogLens reads them into a searchable log, with explanations from the "
    "knowledge base.",
    "Windows events around the selected line": "Select a line and ask for related Windows events around that moment. "
    "Great for finding what really happened.",
    "Open an exported .evtx file": "Exported E V T X files open too.",
    "Follow Windows events live": "Or keep following, and new events arrive live as Windows logs them.",
    "About LogLens": "And finally, the about box. That's everything.",
    "AI: save the answer to your knowledge base": "Happy with the answer? Save it to your knowledge base, "
    "and next time it shows up offline, instantly.",
    OUTRO: "And that is LogLens! Read, filter, understand and explain any log, privately on your own machine. "
    "Thanks for watching!",
}
