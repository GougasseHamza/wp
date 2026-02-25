# Writeup: UofTCTF Lottery Challenge

**Category:** Pwn / Jail

**Difficulty:** Medium-Hard

**Method:** Blind Time-Based Command Injection via Bash Arithmetic Evaluation

## 1. Initial Discovery

The challenge presents a "Lottery" service over a raw TCP connection. When I connected, I had to solve a **Proof-of-Work (PoW)** challenge from `pwn.red`. This is a rate-limiting mechanism to prevent automated spamming of the server.

After solving the PoW, the server prompts:

> Guess the winning ticket (hex):

## 2. Vulnerability Analysis

The input field is vulnerable to **Bash Arithmetic Expansion**. In many CTF challenges involving "calculators" or "hex guesses" written in Bash, user input is passed directly into an arithmetic context like `(( input ))` or `$(( input ))`.

In Bash, arithmetic contexts are surprisingly powerful:

* **Variable Assignment:** You can manipulate environment variables (e.g., `PATH=0`).
* **Comma Operator:** You can chain multiple expressions together.
* **Command Substitution:** You can execute arbitrary shell commands using `$(...)`.

### The Proof of Concept (PoC)

By sending `0, PATH=0`, I got the server to crash with the following error:
`/app/run: line 14: head: command not found`

This confirmed that:

1. The backend is a Bash script.
2. Our input is being evaluated, allowing us to overwrite variables.
3. Standard Error (stderr) is visible, though Standard Output (stdout) is suppressed.

## 3. Exfiltration Strategy

Attempts to read the flag directly via `cat /flag.txt` failed to produce output. Attempts to redirect output to the parent process's file descriptors (`> /proc/$PPID/fd/1`) also failed, likely due to containerization restrictions.

Because I could not see the output, I switched to a **Blind Time-Based Attack**.

### The Challenge: No `sleep`

A typical timing attack relies on the `sleep` command. However, this environment was a minimal Docker container where `/bin/sleep` was not installed.

### The Solution: CPU Busy Loop

To create a detectable delay, I used a Bash-native `for` loop. If a condition (for example, "Is the first character of the flag 'u'?" ) is true, the server executes a loop counting to 3,000,000, which consumes roughly 2 seconds of CPU time.

## 4. The Exploit Logic

I used **Binary Search** to find each character of the flag efficiently. Instead of checking every ASCII character linearly (1 to 127), binary search allows me to find a character in approximately 7 requests.

### The Payload Structure

```bash
0, a[$(if [ $(head -c {index} /flag.txt | tail -c 1 | od -An -t u1) -gt {mid} ]; then for ((i=0;i<3000000;i++)); do :; done; fi)]
```

* **`head -c {index} /flag.txt | tail -c 1`**: Isolates the character at a specific position.
* **`od -An -t u1`**: Converts that character to its decimal ASCII value (e.g., 'u' becomes `117`).
* **`-gt {mid}`**: Compares the value for the binary search.
* **`for...done`**: The "Busy Loop" that creates a detectable timing delay if the condition is met.

## 5. Optimization: Threading

Solving the PoW for every guess is the main bottleneck, taking ~10 seconds per request. A single-threaded solver would take hours to retrieve a 40-character flag.

I implemented a **Threaded Solver** using Python’s `ThreadPoolExecutor`. By running 4 parallel workers, I could process 4 characters (or 4 binary search steps) simultaneously, drastically reducing the total time.

## 6. Execution and Final Flag

The solver extracted the flag character by character. The final flag revealed a self-aware pun on the "Lottery" theme:

**Final Flag:**
`uoftctf{you_won_the_LETtery_(hahahaha_get_it?)}`
