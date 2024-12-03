import operator
import hashlib

# Define constants
UINT256_MAX = 2**256 - 1

def uint256(n):
    return n & UINT256_MAX

# External function for creating function selectors
def string_to_selector(s):
    # Convert string to function selector by taking the first 4 bytes of SHA-3 hash
    h = hashlib.sha3_256(s.encode('utf-8')).digest()[:4]  # Use SHA-3 for Solidity compatibility
    return int.from_bytes(h, 'big')

class TinyVM:
    def __init__(self, 
                 gas_limit=1000, 
                 max_stack_size=1024,  
                 max_memory_size=10000,  
                 max_call_depth=50):
        self.stack = []
        self.memory = bytearray(max_memory_size)  
        self.pc = 0  
        self.instructions = []
        self.gas = gas_limit
        self.functions = {}  
        self.call_stack = []  
        self.running = True  
        self.memory_size = 0  
        
        # Resource limits
        self.max_stack_size = max_stack_size
        self.max_memory_size = max_memory_size
        self.max_call_depth = max_call_depth

        # Supported operations with gas costs
        self.opcodes = {
            'PUSH': (self.push, lambda size: 3 + size),
            'POP': (self.pop, 2),
            'ADD': (self.add, 3),
            'SUB': (self.sub, 3),
            'MUL': (self.mul, 5),
            'DIV': (self.div, 5),
            'MOD': (self.mod, 5),
            'STORE': (self.store, 5),
            'LOAD': (self.load, 3),
            'PRINT': (self.print_stack, 2),
            'DEFINE_FUNC': (self.define_function, 0),
            'CALL_FUNC': (self.call_function, 10),
            'STOP': (self.stop, 0),
            'AND': (self.and_op, 3),
            'OR': (self.or_op, 3),
            'XOR': (self.xor_op, 3),
            'NOT': (self.not_op, 3),
            'JUMPI': (self.jumpi, 10),
            'RETURN': (self.return_op, 0),
        }

    def validate_gas(self, cost):
        if callable(cost):
            cost = cost(len(str(self.instructions[self.pc][1])) if len(self.instructions[self.pc]) > 1 else 0)
        if self.gas < cost:
            raise RuntimeError(f"Out of Gas! Attempted to use {cost} gas, but only {self.gas} remaining.")
        self.gas -= cost

    def push(self, value):
        value_size = len(str(value))  
        self.validate_gas(self.opcodes['PUSH'][1](value_size))
        if len(self.stack) >= self.max_stack_size:
            raise OverflowError(f"Stack size limit ({self.max_stack_size}) exceeded")
        self.stack.append(uint256(value))  # All values on the stack are uint256

    def pop(self):
        self.validate_gas(2)
        if not self.stack:
            raise Exception("Stack Underflow!")
        return self.stack.pop()

    def arithmetic(self, operation):
        if len(self.stack) < 2:
            raise Exception("Insufficient stack items for arithmetic operation.")
        b, a = self.pop(), self.pop()
        result = operation(a, b)
        self.push(result)

    def add(self):
        self.arithmetic(operator.add)

    def sub(self):
        self.arithmetic(operator.sub)

    def mul(self):
        self.arithmetic(operator.mul)

    def div(self):
        self.arithmetic(lambda a, b: a // b if b != 0 else 0)

    def mod(self):
        self.arithmetic(lambda a, b: a % b if b != 0 else 0)

    def and_op(self):
        self.arithmetic(operator.and_)

    def or_op(self):
        self.arithmetic(operator.or_)

    def xor_op(self):
        self.arithmetic(operator.xor)

    def not_op(self):
        self.validate_gas(3)
        if not self.stack:
            raise Exception("Insufficient stack items for NOT operation.")
        a = self.pop()
        self.push(~a & UINT256_MAX)  # Bitwise NOT with mask for 256 bits

    def store(self):
        self.validate_gas(5)
        value = self.pop()
        address = self.pop()
        new_size = max(address + 32, self.memory_size)
        if new_size > self.memory_size:
            memory_gas = self.calculate_memory_gas(new_size)
            self.validate_gas(memory_gas)
            self.memory_size = new_size
        self.memory[address:address+32] = value.to_bytes(32, 'big')

    def load(self):
        self.validate_gas(3)
        address = self.pop()
        new_size = max(address + 32, self.memory_size)
        if new_size > self.memory_size:
            memory_gas = self.calculate_memory_gas(new_size)
            self.validate_gas(memory_gas)
            self.memory_size = new_size
        value = int.from_bytes(self.memory[address:address+32], 'big')
        self.push(value)

    def calculate_memory_gas(self, new_size):
        words = (new_size + 31) // 32
        previous_words = (self.memory_size + 31) // 32
        return 3 * (words - previous_words)

    def print_stack(self):
        self.validate_gas(2)
        print("Stack:", self.stack)

    def stop(self):
        print("Execution halted. Final stack:", self.stack)
        self.running = False

    def define_function(self, func_selector, func_body):
        self.validate_gas(0)
        self.functions[func_selector] = func_body

    def call_function(self):
        self.validate_gas(10)
        func_selector = self.pop()
        
        if func_selector not in self.functions:
            raise Exception(f"Function with selector {hex(func_selector)} not defined.")
        
        call_context = {
            'instructions': self.instructions,
            'pc': self.pc,
            'stack_size': len(self.stack),
            'return_address': self.pc + 1 
        }
        self.call_stack.append(call_context)
        
        self.instructions = self.functions[func_selector]
        self.pc = 0

    def jumpi(self):
        self.validate_gas(10)
        if len(self.stack) < 2:
            raise Exception("Insufficient stack items for JUMPI operation.")
        condition, destination = self.pop(), self.pop()
        if condition != 0:
            if destination >= len(self.instructions):
                raise Exception("Invalid jump destination")
            self.pc = destination
        else:
            self.pc += 1

    def return_op(self):
        if not self.call_stack:
            raise Exception("Return from non-function context")
        
        context = self.call_stack.pop()
        self.instructions = context['instructions']
        self.pc = context['return_address']

    def execute(self, program):
        print("Starting VM Execution...")
        try:
            self.instructions = program
            self.pc = 0
            while self.pc < len(self.instructions) and self.running:
                try:
                    print(f"Executing instruction {self.pc}: {self.instructions[self.pc]}")
                    
                    instr = self.instructions[self.pc]
                    opcode, *args = instr if isinstance(instr, tuple) else (instr, [])

                    if opcode not in self.opcodes:
                        raise Exception(f"Unknown opcode: {opcode}")

                    if args:
                        if opcode == 'DEFINE_FUNC':
                            selector, func_body = args
                            self.define_function(selector, func_body)
                        else:
                            self.opcodes[opcode][0](*args)
                    else:
                        self.opcodes[opcode][0]()

                    if opcode not in ['JUMPI', 'RETURN']:  
                        self.pc += 1

                    if self.pc >= len(self.instructions) and self.call_stack:
                        self.return_op()  # Automatically return if we've reached the end of a function

                except Exception as e:
                    print(f"Error during execution at instruction {self.pc}: {e}")
                    break
        except Exception as e:
            print(f"VM Execution Failed: {e}")
        finally:
            print(f"Final VM State - Stack: {self.stack}, Memory: {self.memory[:self.memory_size]}, Gas Remaining: {self.gas}")

# Example usage
def main():
    # Here, we convert function names to selectors externally before VM execution
    double_selector = string_to_selector('double()')
    program = [
        ('PUSH', 10),
        ('PUSH', 20),
        ('ADD',),
        ('DEFINE_FUNC', double_selector, [
            ('POP',),
            ('PUSH', 2),
            ('MUL',),
            ('PRINT',),
            ('RETURN',),
        ]),
        ('PUSH', double_selector),  # Push the function selector
        ('CALL_FUNC',),
        ('PUSH', 5),
        ('PUSH', 3),
        ('AND',),
        ('PRINT',),
        ('PUSH', 5),
        ('PUSH', 3),
        ('OR',),
        ('PRINT',),
        ('PUSH', 5),
        ('PUSH', 3),
        ('XOR',),
        ('PRINT',),
        ('PUSH', 5),
        ('NOT',),
        ('PRINT',),
        ('PUSH', 1),  
        ('PUSH', 0),  
        ('JUMPI',),
        ('PUSH', 42),
        ('PRINT',),
        ('STOP',),
    ]

    vm = TinyVM(gas_limit=1000, max_stack_size=1024)
    vm.execute(program)

if __name__ == "__main__":
    main()
