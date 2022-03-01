
// map chunk tails, when there are no input blocks.
int map_chunk_tail(PAR3_CTX *par3_ctx);


// These store all input files on memory.

// map input files into input blocks without deduplication
int map_input_block_simple(PAR3_CTX *par3_ctx);

// map input files into input blocks without slide search
int map_input_block(PAR3_CTX *par3_ctx);

// map input files into input blocks with slide search
int map_input_block_slide(PAR3_CTX *par3_ctx);

