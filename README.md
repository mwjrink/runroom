# RunRoom

Run an app in a sandbox using bubblewrap and systemd to restrict files. This is little more than a command wrapper with a coordination daemon.

## Usecase

Run agents/harnesses in a directory and give them read only access to other files. Limit their cpu cores (I set mine to the last physical cores to keep core 0-3 for ui responsiveness) & memory.
