Compile instructions:

	Client:
		$cd Client/
		$javac Client.java
	Host:
		$cd Host/
		$javac Host.java

Run instructions:
	
	Client:
		$cd Client/
		$java Client

	Host:
		$cd Host/
		$java Host

Usage instructions:
	-When compiling you must be in either host or client directory otherwise the JRE cannot compile the other files sequentially
	-Host must be running first and you must have specified the password before client can connect.
	-Diffie-hellman parameters are generated each time a password is set.
	-Once a client sends 'exit', on the host terminal you must press enter to listen for new client UDP packets because the main thread haults at 	scanner.nextLine();
	

