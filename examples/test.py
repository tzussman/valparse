from valparse import Parser

a = Parser('bad-test.xml')
print(a.__str__())

b = Parser('bad.xml')
print(b.__str__())
