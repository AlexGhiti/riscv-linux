def test_main(c, kernel_version):
    res = c.run("test -d /opt/sources/linux/Makefile || true")
    if res.exited:
        print("No linux sources found")
        return

    # Compile the libperf (shared with the host via a virtio device)
    c.sudo("bash -c 'cd /opt/sources/linux/tools/lib/perf && make'")

    # Compile the test
    c.put("tests/all/perf/test_perf_mmap.c")
    c.run("gcc -I/opt/sources/linux/tools/lib/perf/include test_perf_mmap.c -o test_perf_mmap -lperf -L/opt/sources/linux/tools/lib/perf/ -g")

    # Run the test
    c.put("tests/all/perf/run.sh")
    res = c.sudo("bash run.sh")

    # Check the ouput
    # TODO

test_main(c, kernel_version)
