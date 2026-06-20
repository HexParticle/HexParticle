from . import ast_nodes

import enum


PROTOCOL_FIELDS = [
    # TCP protocol fields
    'TCP.WIN_SIZE', 'TCP.FLAGS', 'TCP.SEQ_NUM', 
    'TCP.ACK_NUM', 'TCP.DATA_OFF', 'TCP.CKSUM', 
    'TCP.URG_PTR', 'TCP.SRC_PORT', 'TCP.DST_PORT',

    # IP protocol fields
    'IP.VER', 'IP.IHL', 'IP.TTL', 'IP.CKSUM',
    'IP.PROTO', 'IP.FRAG_OFF', 'IP.LEN', 'IP.ID',
    'IP.DSCP', 'IP.ECN', 'IP.DF', 'IP.MF', 'IP.SRC_HOST',
    'IP.DST_HOST'
]


FIELD_OFF_SIZE = {
    'TCP.SRC_PORT':     (0, 2),
    'TCP.DST_PORT':     (2, 2),
    'TCP.SEQ_NUM':      (4, 4),
    'TCP.ACK_NUM':      (8, 4),
    'TCP.WIN_SIZE':     (14, 2),
    'TCP.CKSUM':        (16, 2),
    'TCP.URG_PTR':      (18, 2),
}


class EndpointType(enum.Enum):
    SOURCE = enum.auto()
    DESTINATION = enum.auto()


def emit_bpf_endpoint(ast: ast_nodes.FilterStatement, et: EndpointType):
    fragments = []

    if et == EndpointType.SOURCE:
        if ast.source.ip:
            fragments.append(f'src host {ast.source.ip}')
    
        if ast.source.port:
            if ast.source.ip is None:
                raise ValueError("source port without an IP is not supported.")

            fragments.append(f'src port {ast.source.port}')

        if ast.source.mac:
            fragments.append(f'ether src {ast.source.mac}')
    else:
        if ast.destination.ip:
            fragments.append(f'dst host {ast.destination.ip}')
    
        if ast.destination.port:
            if ast.destination.ip is None:
                raise ValueError("destination port without an IP is not supported.")

            fragments.append(f'dst port {ast.destination.port}')

        if ast.destination.mac:
            fragments.append(f'ether dst {ast.destination.mac}')

    if len(fragments) == 0: return None

    return " and ".join(fragments)


def emit_bpf_endpoints(ast: ast_nodes.FilterStatement):
    endpoint_str = emit_bpf_endpoint(ast, EndpointType.SOURCE)
    endpoint_str = f'{endpoint_str} and {emit_bpf_endpoint(ast, EndpointType.DESTINATION)}'
    return endpoint_str


def emit_bpf_protocol_field_condition_for_tcp(field: str, op: str, value: str):
    off_size = FIELD_OFF_SIZE.get(field)
    size = off_size[1]

    if size == 1:
        return f"tcp[{off_size[0]}] {op} {value}"
    else:
        return f"tcp[{off_size[0]}:{off_size[1]}] {op} {value}"


def emit_bpf_protocol_field_condition(condition: ast_nodes.Condition):
    field = condition.field

    if field not in PROTOCOL_FIELDS:
        raise ValueError(f"'{field}' cannot be identified as a protocol field.")

    if field.startswith('TCP'):
        return emit_bpf_protocol_field_condition_for_tcp(field, condition.operator, condition.value)
    elif field.startswith('IP'):
        pass


def emit_bpf_where_clause(where_clause: ast_nodes.WhereClause):
    if where_clause is None: return ''

    fragments = []
    conditions = where_clause.condition_list
    if where_clause and len(conditions) > 0:
        for condition in conditions:
            field_condition_result = emit_bpf_protocol_field_condition(condition)
            if field_condition_result:
                fragments.append(field_condition_result)

    return " and ".join(fragments)


def emit_bpf(ast: ast_nodes.FilterStatement):
    fragments = filter(
        lambda x: x != '', 
        [emit_bpf_endpoints(ast), emit_bpf_where_clause(ast.where_clause)]
    )
    return " and ".join(fragments)