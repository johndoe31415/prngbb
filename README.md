# prngbb
When writing to disk and there's a loss of power during the write, what are the
guarantees that the underlying block device provides? Is sector atomicity
guaranteed or may corruption happen anywhere? Are blocks written consecutively
in FIFO-fashion or may the controller reorder them before commening writes?

To answer this for a particular device, prngbb has been written. It essentially
fills a portion of a block device with a reversible PRNG pattern with variable
seed. It does this forever, in a bounded-buffer fashion. You run it, then wait
until it has a few blocks written (it syncs after each iteration), then cut
power.

Afterwards, you run the Python script to determine what happened.

## License
GNU GPL-3
