# Demonstration and submission checklist

## Verification status

The **31 automated tests pass** in this workspace with Python 3.12.14 and Scapy 2.8.0. The synthetic offline demo successfully analyzes all 10 sample packets. Commands were run with interface discovery permitted; raw capture privileges remain unavailable.

The live capture backend is implemented, but an actual network-interface capture must be verified on your Linux computer or VM. Iterable and pipe-based capture-loop tests do not replace this live check.

## Linux VM acceptance checks

Follow the HTTP and ping demonstration in the README, then complete these checks:

- [ ] List interfaces and identify `lo`.
- [ ] Capture a local HTTP request with the `tcp port 8000` filter.
- [ ] Confirm source/destination addresses, TCP ports, packet sizes, and HTTP text appear.
- [ ] Reopen the saved PCAP using `--read` and confirm the packet count matches.
- [ ] Capture loopback ping and confirm ICMP is displayed.
- [ ] Run with `--count 2 --timeout 30`, generate traffic, and confirm no more than two packets are displayed.
- [ ] Run with `--timeout 2 --filter "udp port 65534"` while generating no matching traffic; confirm a zero-packet summary after about two seconds.
- [ ] Start a capture with `--count 10000 --timeout 60 --write captures/interrupt-demo.pcap`, generate an HTTP request, and press Ctrl+C. Confirm the partial summary and reopen the saved file.
- [ ] Try a nonexistent interface and an invalid filter such as `"tcp and and"`; confirm readable errors.
- [ ] Try a capture as an ordinary user without capture capabilities; confirm a permission error.
- [ ] Try an existing output filename; confirm it is preserved.

Use a new filename for each saved capture. The commands assume you are in the project directory and have installed the README's dependencies.

## Video outline — approximately 3–4 minutes

1. **Introduction, 20 seconds:** State your name, CodeAlpha internship, and Task 1: Basic Network Sniffer. Explain that the tool captures and analyzes network packets using Python and Scapy.
2. **Code walkthrough, 45–60 seconds:** Show argument parsing, `analyze_packet()`, payload formatting, and the capture callback. Explain source/destination addresses, ports, protocol detection, and `store=False`.
3. **Live capture, 60–90 seconds:** Start the local HTTP server, run the sniffer on `lo`, and generate a request with curl. Identify the addresses, TCP port 8000, and HTTP request payload. Briefly demonstrate ping/ICMP.
4. **Saved capture, 20–30 seconds:** Reopen the recorded PCAP and show the summary. Explain that the committed sample is synthetic and separate from your live capture.
5. **Verification and repository, 20–30 seconds:** Run the tests, show the README, and display your GitHub repository URL.

If recording before VM verification, clearly describe the workspace example as an offline sample demonstration. Record the live section on the VM once it has been verified.

## Prepare GitHub

Create a GitHub repository named `CodeAlpha_BasicNetworkSniffer`. Upload the project files, including the synthetic sample. The virtual environment, caches, and live PCAP files should be excluded by `.gitignore`.

If using Git, run the following from the project directory after replacing the URL with your own repository URL:

```bash
git init
git add .
git status --short
git commit -m "Add CodeAlpha basic network sniffer"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/CodeAlpha_BasicNetworkSniffer.git
git push -u origin main
```

Before committing, check that `.venv/` and your live captures are absent from `git status`. The sample PCAP and its generator should be included. Open the README and source on GitHub after uploading to confirm they render correctly.

## Submission checklist

- [ ] Complete the Linux VM live checks above.
- [ ] Run `.venv/bin/python -m unittest discover -s tests -v` successfully.
- [ ] Upload the full project to the correctly named GitHub repository.
- [ ] Record the explanation video with the live demonstration.
- [ ] Post the project video on LinkedIn, tag `@CodeAlpha`, and include the GitHub repository link.
- [ ] Share internship status on LinkedIn if you have not already done so, as requested in the brief.
- [ ] Submit the requested links through the submission form shared in your internship WhatsApp group.

This completes the Task 1 project. The internship brief separately asks for a total of two or three tasks for certificate eligibility.
