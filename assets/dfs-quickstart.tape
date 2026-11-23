Output assets/dfs-quickstart.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 640
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type "export PATH=/tmp/dfs-demo-b/bin:$PATH HOME=/tmp/dfs-demo-b/home DFS_LANG=en PS1='$ '" Enter
Type "cd /tmp/dfs-demo-b && clear" Enter
Sleep 500ms
Show

Type "# Install: curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash" Enter
Sleep 800ms

Type "dfs start --port 19120 --no-hub" Enter
Sleep 2.5s

Type "dfs push ./dataset" Enter
Sleep 2s

Type "dfs ls" Enter
Sleep 1.5s

Type "dfs pull ./restored" Enter
Sleep 1.5s

Type "ls -l ./restored" Enter
Sleep 3s

Hide
Type "dfs stop >/dev/null 2>&1" Enter
Sleep 500ms
