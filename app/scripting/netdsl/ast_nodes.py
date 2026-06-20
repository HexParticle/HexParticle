import typing 

# An endpoint is something that can receive data such as an Ethernet port.
class Endpoint():
    def __init__(self, ip: str = None, mac: str = None, port: int = None):
        self.ip = ip
        self.port = port
        self.mac = mac    


class Condition:
    def __init__(self, field: str, operator: str, value: str):
        self.field = field
        self.operator = operator
        self.value = value


class ConditionList:
    def __init__(self, conditions: typing.List[Condition]):
        self.conditions = conditions

    def __len__(self):
        return len(self.conditions)

    def __iter__(self):
        return iter(self.conditions)

    def __add__(self, other):
        return self.conditions + other


class WhereClause:
    def __init__(self, condition_list: ConditionList):
        self.condition_list = condition_list


class FilterStatement:
    def __init__(self, source: Endpoint, destination: Endpoint, where_clause: WhereClause = None):
        self.source = source
        self.destination = destination
        self.where_clause = where_clause