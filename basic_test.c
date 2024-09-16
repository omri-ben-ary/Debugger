int bar(int a, int b);

int foo(int a, int b) {
	if (a == 0 || b == 0)
		return 0;
	a--;
	b--;	
	return a+b + bar(a,b);
}

int bar(int a, int b) {
 if (a == 0 || b == 0)
		return 0;
	
	return 1+ foo(a,b);
}

int main () {

 int x = bar(2,2);
 int y= foo(2,2);
 
 return 0;
}
