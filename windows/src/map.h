
// map chunk tails, when there are no input blocks.
int map_chunk_tail(PAR3_CTX *par3_ctx);

// map input file slices into input blocks without deduplication
int map_input_block_simple(PAR3_CTX *par3_ctx);
int map_input_block_trial(PAR3_CTX *par3_ctx);

// map input file slices into input blocks without slide search
int map_input_block(PAR3_CTX *par3_ctx);

// map input file slices into input blocks with slide search
int map_input_block_slide(PAR3_CTX *par3_ctx);

