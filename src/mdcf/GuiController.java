package mdcf;
import java.io.File;
import java.io.IOException;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/* This should contain code which handles GUI events */
public class GuiController {	
	
	@FXML private Stage stage;	
	
	// Device Model Certificate Request Tab
	@FXML protected TextField modelOutputFileChooserText;
	@FXML protected Button generateModelCertRequestButton;
	@FXML protected ChoiceBox modelAlgorithmChoiceBox;
	@FXML protected ChoiceBox modelKeySizeChoiceBox;
	@FXML protected TextField modelValidDaysTextField;
	@FXML protected ChoiceBox modelStateOrProvenceChoiceBox;
	@FXML protected ChoiceBox modelCountryChoiceBox;
	@FXML protected TextField modelDeviceNameTextField;
	@FXML protected TextField modelManufacturerTextField;
	@FXML protected TextField modelEmailTextField;
	
	
	// Device Instance Tab
	@FXML protected TextField instanceOutputFileChooserText;
	@FXML protected TextField instanceRootCertFileChooserText;
	@FXML protected TextField instanceMfgCertFileChooserText;
	@FXML protected TextField instanceDevTypeCertFileChooserText;
	@FXML protected Button generateInstanceButton;
	@FXML protected ChoiceBox instanceAlgorithmChoiceBox;
	@FXML protected ChoiceBox instanceKeySizeChoiceBox;
	@FXML protected TextField instanceValidDaysTextField;
	
	// Device Model Request Signing Tab
	
	public void setStage(Stage stage) {
		this.stage = stage;
		
		//handleGenerateModelCertRequestButtonAction(new ActionEvent());
	}
	
	
	///////////////////////////////////////////////////////////////////////
	//        Device Model Certificate Request Event Handlers
	///////////////////////////////////////////////////////////////////////
	@FXML protected void handleGenerateModelCertRequestButtonAction(ActionEvent event) throws IOException {
		//TODO: create OpenSSL command and run it.
		
		/* Default Values */
		String keyAlgorithm = "rsa";
		String keySize = "2048";
		String privateKeyFileName = "private";
		String csrFileName = "CSR";
		String country = "US"; //Country codes MUST be 2 characters long
		String state = "KS";
		String locale = "";
		String organization = "KSU";
		String orgUnit = "";
		String email = "csalazar@ksu.edu";
		String commonName = "santoslab.org";

		switch (modelAlgorithmChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid algorithm selection!");
			break;
		case 0 : //SHA1withDSA
			keyAlgorithm = "dsa";
			break;
		case 1 : //SHA1withRSA
			keyAlgorithm = "rsa";
			break;
		default:
			break;
		}

		switch (modelKeySizeChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid key size selection!");
			break;
		case 0 : //2048
			keySize = "2048";
			break;
		case 1 : //4096
			keySize = "4096";
			break;
		default:
			break;
		}
		
		if (!modelOutputFileChooserText.getText().isEmpty()) {
			privateKeyFileName = modelOutputFileChooserText.getText() + "priv";
			csrFileName = modelOutputFileChooserText.getText();
		}
		
		if (modelCountryChoiceBox.getSelectionModel().getSelectedIndex() != -1) {
			country = modelCountryChoiceBox.getSelectionModel().getSelectedItem().toString();
			System.out.println("country: " + country);
		}
		
		if (modelStateOrProvenceChoiceBox.getSelectionModel().getSelectedIndex() != -1) {
			state = modelStateOrProvenceChoiceBox.getSelectionModel().getSelectedItem().toString();
			System.out.println("state: " + state);
		}
		
		//TODO: add locale to GUI (replace phone)
		//TODO: add Organization to GUI (replace email)
		//TODO: add Organizational Unit to GUI
		//TODO: figure out how to attach other fields to CSR
		
		if (!modelDeviceNameTextField.getText().isEmpty()) {
			commonName = modelDeviceNameTextField.getText();
		}
		
		if(!modelEmailTextField.getText().isEmpty()) {
			email = modelEmailTextField.getText();
		}
		
		if(!modelManufacturerTextField.getText().isEmpty()) {
			organization = modelManufacturerTextField.getText();
		}

		commonName="N900";
		organization = "Nellcor";
		email="cert@example.org";
		locale="manhattan";
		state="kansas";
		country="US";
		
		String dn = "CN="+commonName+" O="+organization+" email="+email+" L="+locale+" ST="+state+" C="+country;
		System.out.println("Distinguished Name :" + dn);
		
		CreateX509Certificate certificate = new CreateX509Certificate();
		certificate.generate(dn,csrFileName,keyAlgorithm);
		
		int a=0;
		
		if(a==0) {
			System.out.println("Certificate Request Generated");
		}
		else {
			System.err.println("Certificate Request Generation Failed.");
		} 

	}
	
	
	@FXML protected void handleModelFileDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		if (f != null) modelOutputFileChooserText.setText(f.getAbsolutePath());
		checkModelValidity();
	}
	
	/* This is a method that should be called whenever a UI event occurs */
	protected void checkModelValidity() {
		//otherModelValidityChecks();
		/* Make sure all required fields are filled out */
		/*boolean validity = modelOutputFileChooserTextValidity() && 
				otherModelValidityChecks();
		*/
		boolean validity = true; // For now, since there isn't enough time to get the validation right.
		
		//TODO: make sure that the certificate files loaded by the user are valid
		// This should include a visual cue for the user (a green check or red x)
		
		if (validity == true) {
			generateModelCertRequestButton.setDisable(false);
		}
		else {
			generateModelCertRequestButton.setDisable(true);
		}
	}
	
	private boolean otherModelValidityChecks() {
		boolean validity = false;
		if (modelAlgorithmChoiceBox.getSelectionModel().getSelectedIndex() == -1) {
			return validity;
		}
		if (modelKeySizeChoiceBox.getSelectionModel().getSelectedIndex() == -1) {
			return validity;
		}
		if (!modelValidDaysTextField.getText().matches("[0-9]+")) {
			System.out.println("regex fail");
			System.out.flush();
			return validity; //regex for matching one or more digits.
		}
		if (modelCountryChoiceBox.getSelectionModel().getSelectedIndex() == -1) {
			return validity;
		}
		if (modelStateOrProvenceChoiceBox.getSelectionModel().getSelectedIndex() == -1) {
			return validity;
		}
		if(!modelDeviceNameTextField.getText().matches("[a-zA-Z0-9]+")) {
			return validity; //mean to match if there is at least one character or letter
		}
		if(!modelEmailTextField.getText().matches("[a-zA-Z0-9]+@[a-zA-Z0-9]+.[a-zA-Z0-9]+")) {
			return validity; //mean to match if there is at least one character or letter
		}
		if(!modelManufacturerTextField.getText().matches("[a-zA-Z0-9]+")) {
			return validity; //mean to match if there is at least one character or letter
		}
		validity = true;
		return validity;
	}
	
	private boolean modelOutputFileChooserTextValidity()
	{
		String t = modelOutputFileChooserText.getText();
		boolean validity = false;
		
		//if (!(t.endsWith(".crt") || t.endsWith(".pem") || t.endsWith(".der"))) {
		if (t.isEmpty()) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		validity = true;
		
		return validity;
	}
	
	@FXML protected void handleModelEnterKeyAction(ActionEvent event) {
		checkModelValidity();
	}
	
	///////////////////////////////////////////////////////////////////////
	//        Device Instance Tab Event Handlers
	///////////////////////////////////////////////////////////////////////
	
	
	@FXML protected void handleRootCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceRootCertFileChooserText.setText(f.getAbsolutePath());
		checkInstanceValidity();
	}
	
	@FXML protected void handleMfgCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceMfgCertFileChooserText.setText(f.getAbsolutePath());
		checkInstanceValidity();
	}
	
	@FXML protected void handleDevTypeCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceDevTypeCertFileChooserText.setText(f.getAbsolutePath());
		checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceFileDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceOutputFileChooserText.setText(f.getAbsolutePath());
		checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceValidDaysTextFieldAction(ActionEvent event) {
		checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceKeySizeChoiceBoxMouseExit(MouseEvent event) {
		checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceAlgorithmChoiceBoxMouseExit(MouseEvent event) {
		checkInstanceValidity();
	}
	
	/* This is a method that should be called whenever a UI event occurs */
	protected void checkInstanceValidity() {
		/* Make sure all required fields are filled out */
		boolean validity = instanceOutputFileChooserTextValidity() && 
				instanceRootCertFileChooserTextValidity() &&
				instanceMfgCertFileChooserTextValidity() &&
				instanceDevTypeCertFileChooserTextValidity() &&
				otherInstanceValidityChecks();
		
		//TODO: make sure that the certificate files loaded by the user are valid
		// This should include a visual cue for the user (a green check or red x)
		
		if (validity == true) {
			generateInstanceButton.setDisable(false);
		}
		else {
			generateInstanceButton.setDisable(true);
		}
	}
	
	private boolean otherInstanceValidityChecks() {
		boolean validity = false;
		if (instanceAlgorithmChoiceBox.getSelectionModel().getSelectedIndex() == -1) {
			return validity;
		}
		if (instanceKeySizeChoiceBox.getSelectionModel().getSelectedIndex() == -1) {
			return validity;
		}
		if (!instanceValidDaysTextField.getText().matches("[0-9]+")) {
			System.out.println("regex fail");
			System.out.flush();
			return validity; //regex for matching one or more digits.
		}
		validity = true;
		return validity;
	}
	
	private boolean instanceOutputFileChooserTextValidity()
	{
		String t = instanceOutputFileChooserText.getText();
		boolean validity = false;
		
		if (t.isEmpty()) return validity;
		if (!new File(t).exists()) {
			//file with path t does not exist.
			return validity;
		}
		if (!(t.endsWith(".crt") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		validity = true;
		
		return validity;
	}
	
	private boolean instanceRootCertFileChooserTextValidity()
	{
		String t = instanceRootCertFileChooserText.getText();
		boolean validity = false;
		
		if (t.isEmpty()) return validity;
		if (!new File(t).exists()) {
			//file with path t does not exist.
			return validity;
		}
		if (!(t.endsWith(".crt") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		validity = true;
		
		return validity;
	}

	private boolean instanceMfgCertFileChooserTextValidity()
	{
		String t = instanceMfgCertFileChooserText.getText();
		boolean validity = false;
		
		if (t.isEmpty()) return validity;
		if (!new File(t).exists()) {
			//file with path t does not exist.
			return validity;
		}
		if (!(t.endsWith(".crt") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		validity = true;
		
		return validity;
	}
	
	private boolean instanceDevTypeCertFileChooserTextValidity()
	{
		String t = instanceDevTypeCertFileChooserText.getText();
		boolean validity = false;
		
		if (t.isEmpty()) return validity;
		if (!new File(t).exists()) {
			//file with path t does not exist.
			return validity;
		}
		if (!(t.endsWith(".crt") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		validity = true;
		
		return validity;
	}
	
	///////////////////////////////////////////////////////////////////////
	//        Device Model Certificate Signing Event Handlers            //
	///////////////////////////////////////////////////////////////////////
	@FXML protected TextField modelSignRootCertFileChooserText;
	@FXML protected TextField modelSignMfgCertFileChooserText;
	@FXML protected TextField modelSignDevTypeCertFileChooserText;
	@FXML protected TextField modelSignOutputFileChooserText;
	@FXML protected TextField modelSignValidDaysTextField;
	
	/*
	 * Need to place a CA configuration file in the directory this command is ran from.
	 */
	@FXML protected void handleModelSignButtonAction(ActionEvent event) {
		String currentDirectory = System.getProperty("user.dir");
		String csrFileName = "csr.CSR";
		String outputFileName = currentDirectory + File.separator + "signedcerts" + File.separator +"devModelCert.crt";
		String caCertFileName = "cacert.pem";
		String caCertPrivateKeyFileName = currentDirectory + File.separator + "private" + File.separator + "cakey.pem"; //private key
		String caPassword = "password";
		String configFileName = "caconfig.cnf";
		String validDays = "1826";
		
		//TODO: make the root cert file chooser actually work
		
		//TODO: Make the manufacturer cert file chooser actually work
		//TODO: Make the manufacturer cert file actually meaningful in the cert chain (later)
		
		
		if (!modelSignDevTypeCertFileChooserText.getText().isEmpty()) {
			csrFileName = modelSignDevTypeCertFileChooserText.getText();
		}
		
		if (!modelSignValidDaysTextField.getText().isEmpty()) {
			validDays = modelSignValidDaysTextField.getText();
		}
		
		if (!modelSignOutputFileChooserText.getText().isEmpty()) {
			outputFileName = currentDirectory + File.separator + "signedcerts" + File.separator + modelSignOutputFileChooserText.getText();
		}
		
		String[] command;
		
		command = new String[] {
				"/bin/sh", "-c", "openssl ca -batch -in " + csrFileName + 
				" -out " + outputFileName + " -keyfile " + caCertPrivateKeyFileName +
				" -cert " + caCertFileName + " -passin pass:" + caPassword + " -config " + configFileName + 
				" -days " + validDays
		};

	
	/* Used only for debugging! */
	for (String s : command) {
		System.out.print(s + " ");
	}
	System.out.println();
	
	try {			

		//Runtime.getRuntime().exec(command);
		Process p = new ProcessBuilder(command).start();
		
		if(p.waitFor()==0) {
			System.out.println("Certificate Request Generated");
		}
		else {
			System.err.println("Certificate Request Generation Failed.");
		}
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InterruptedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} 
	}
	
	
	@FXML protected void handleModelSignRootCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Select a Root Certificate File.");
		File f = fileChooser.showOpenDialog(stage);
		if (f == null) { System.err.println("Null File."); }
		else {
			modelSignRootCertFileChooserText.setText(f.getName());
		}
		//checkModelSignValidity();
	}
	
	@FXML protected void handleModelSignMfgCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		modelSignMfgCertFileChooserText.setText(f.getName());
		//checkModelSignValidity();
	}
	
	@FXML protected void handleModelSignDevTypeCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		modelSignDevTypeCertFileChooserText.setText(f.getName());
		//checkModelSignValidity();
	}
	
	@FXML protected void handleModelSignFileDialogButtonAction(ActionEvent event) {
		DirectoryChooser fileChooser = new DirectoryChooser();
		File f = fileChooser.showDialog(stage);
		String s = f.getPath();
		//modelSignOutputFileChooserText.setText(s);
		//checkModelSignValidity();
	}
	
	private void checkModelSignValidity() {
		//TODO: write me!
	}
}