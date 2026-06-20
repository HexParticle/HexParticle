from . import parser
from . import bpf_emitter

if __name__ == "__main__":
    dsl_input = "FROM 192.168.1.1:3000@aa:bb:cc:dd:ee:ff TO 192.168.1.2:1090@ff:ee:dd:cc:bb:aa WHERE TCP.SRC_PORT = 12345, TCP.DST_PORT = 54321"
    
    ast_root = parser.parse(dsl_input)

    if ast_root:
        bpf_output = bpf_emitter.emit_bpf(ast_root)
        print(f"NetDSL Input:  {dsl_input}\n\n")
        print(f"BPF Literal:   \"{bpf_output}\"")