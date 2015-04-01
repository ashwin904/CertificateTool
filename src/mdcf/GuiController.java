package mdcf;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

import sun.misc.BASE64Encoder;
import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;
import sun.security.x509.X500Name;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/* This should contain code which handles GUI events */
public class GuiController {	
	
	@FXML private Stage stage;	
	
	
	// Device Model Certificate Request Tab
		@FXML protected TextField manufacturerOutputFileChooserText;
		@FXML protected Button generatemanufacturerCertRequestButton;
		@FXML protected ChoiceBox manufacturerAlgorithmChoiceBox;
		@FXML protected ChoiceBox manufacturerKeySizeChoiceBox;
		@FXML protected TextField manufacturerValidDaysTextField;
		@FXML protected ChoiceBox manufacturerStateOrProvenceChoiceBox;
		@FXML protected ChoiceBox manufacturerCountryChoiceBox;
		//@FXML protected TextField manufacturerDeviceNameTextField;
		@FXML protected TextField manufacturerManufacturerTextField;
		@FXML protected TextField manufacturerEmailTextField;
		@FXML protected Label manufacturerCertErrorLabel;
	
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
	@FXML protected Label modelErrorLabel; 
	

	
	// Device Model Request Signing Tab
	
	public void setStage(Stage stage) {
		this.stage = stage;
	}
	
	///////////////////////////////////////////////////////////////////////
	//        Manufacturer Certificate Request Event Handlers
	///////////////////////////////////////////////////////////////////////
	@FXML protected void handleGenerateManufacturerCertRequestButtonAction(ActionEvent event) throws IOException {

		/* Default Values */
		String keyAlgorithm="";
		String keySize="";
		String csrFileName="";
		String country="";
		String state="";
		String organization="";
		String email="";

		try {
			

			if(!manufacturerManufacturerTextField.getText().isEmpty()) {
				organization = manufacturerManufacturerTextField.getText();
			}
			else {
				manufacturerCertErrorLabel.setText("Error : Manufacturer value is empty.");
				throw new Exception("");
			}
			
			if (manufacturerCountryChoiceBox.getSelectionModel().getSelectedIndex() != -1) {
				country = manufacturerCountryChoiceBox.getSelectionModel().getSelectedItem().toString();
			}
			else {
				manufacturerCertErrorLabel.setText("Error : Country value is empty.");
				throw new Exception("");
			}

			if (manufacturerStateOrProvenceChoiceBox.getSelectionModel().getSelectedIndex() != -1) {
				state = manufacturerStateOrProvenceChoiceBox.getSelectionModel().getSelectedItem().toString();
			}
			else {
				manufacturerCertErrorLabel.setText("Error : State value is empty.");
				throw new Exception("");
			}
			
			if(!manufacturerEmailTextField.getText().isEmpty()) {
				email = manufacturerEmailTextField.getText();
			}
			else {
				manufacturerCertErrorLabel.setText("Error : Email value is empty.");
				throw new Exception("");
			}
			
		switch (manufacturerAlgorithmChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid algorithm selection!");
			manufacturerCertErrorLabel.setText("Error : Invalid algorithm selection!");
			throw new Exception("Invalid algorithm selection!");
		case 0 : //SHA1withDSA
			keyAlgorithm = "DSA";
			break;
		case 1 : //SHA1withRSA
			keyAlgorithm = "RSA";
			break;
		default:
			break;
		}

		switch (manufacturerKeySizeChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid key size selection!");
			manufacturerCertErrorLabel.setText("Error : Invalid Key selection!");
			throw new Exception("Invalid key size selection!");
		case 0 : //1024
			keySize = "1024";
			break;
		case 1 : //2048
			keySize = "2048";
			break;
		default:
			break;
		}

		if (!manufacturerOutputFileChooserText.getText().isEmpty()) {
			csrFileName =manufacturerOutputFileChooserText.getText();
		}
		else {
			manufacturerCertErrorLabel.setText("Error : Output file value is empty.");
			throw new Exception("");
		}

		String dn = " O="+organization+" email="+email+" ST="+state+" C="+country;
		System.out.println("Distinguished Name :" + dn);
		System.out.println("Algorithm: " + keyAlgorithm);
		System.out.println("Key Size: " +keySize);

		
		X500Name x500Name = new X500Name(
                "",               // CN
                email,               // OU
                organization,          // O
                "",          // L
                state,               // S
                country); 
		
		CSRRequest csrRequest = new CSRRequest();
		HandleCSRRequest handleCSRRequest = new HandleCSRRequest();

			PKCS10 pkcs10 = csrRequest.generatePKCS10(keyAlgorithm, keySize, x500Name,csrFileName,"ManfPublicKey.pem","ManfPrivateKey.pem");
			handleCSRRequest.handleRequest(pkcs10, csrFileName.replace(".cer", ""),"CA");
			if (pkcs10!=null){
				manufacturerCertErrorLabel.setText("Msg: Certificate "+csrFileName + " created.");
				System.out.println("Certificate Request Generated");
				System.out.println("Certificate Created");
			}
			else {
				manufacturerCertErrorLabel.setText("Error: Certificate creation failed.");
				System.err.println("Certificate Request Generation Failed.");
			} 
			
		} catch (Exception e) {
			//manufacturerCertErrorLabel.setText("Error: Certificate creation failed.");
			e.printStackTrace();
		}

	}
	
	@SuppressWarnings("unchecked")
	@FXML protected void handleManufacturerCertDemoButtonAction(ActionEvent event) throws IOException {

		manufacturerManufacturerTextField.setText("johnson&johnson");
		manufacturerEmailTextField.setText("jnj_company@outlook.com");
		manufacturerOutputFileChooserText.setText("manf_johnson.cer");
		manufacturerValidDaysTextField.setText("30");
		manufacturerAlgorithmChoiceBox.getSelectionModel().select(0);
		manufacturerKeySizeChoiceBox.getSelectionModel().select(0);
		manufacturerCountryChoiceBox.getSelectionModel().select(0);
		manufacturerStateOrProvenceChoiceBox.getSelectionModel().select(0);
		
	}
	
	
	///////////////////////////////////////////////////////////////////////
	//        Device Model Certificate Request Event Handlers
	///////////////////////////////////////////////////////////////////////
	@FXML protected void handleGenerateModelCertRequestButtonAction(ActionEvent event) throws IOException {
		
		/* Default Values */
		String keyAlgorithm="";
		String keySize = "";
		String csrFileName = "";
		String country = "";
		String state = "";
		String locale = "";
		String organization = "";
		String orgUnit = "";
		String email = "";
		String commonName = "";

		try{
			
			if (!modelDeviceNameTextField.getText().isEmpty()) {
				commonName = modelDeviceNameTextField.getText();
			}
			else {
				modelErrorLabel.setText("Error : Device name value is empty.");
				throw new Exception("");
			}
			
			if (modelCountryChoiceBox.getSelectionModel().getSelectedIndex() != -1) {
				country = modelCountryChoiceBox.getSelectionModel().getSelectedItem().toString();
				System.out.println("country: " + country);
			}
			else {
				modelErrorLabel.setText("Error : Country value is empty.");
				throw new Exception("");
			}
			
			if (modelStateOrProvenceChoiceBox.getSelectionModel().getSelectedIndex() != -1) {
				state = modelStateOrProvenceChoiceBox.getSelectionModel().getSelectedItem().toString();
				System.out.println("state: " + state);
			}
			else {
				modelErrorLabel.setText("Error : State value is empty.");
				throw new Exception("");
			}
			
			if(!modelManufacturerTextField.getText().isEmpty()) {
				organization = modelManufacturerTextField.getText();
			}
			else {
				modelErrorLabel.setText("Error : Manufacturer name is empty.");
				throw new Exception("");
			}
			
			if(!modelEmailTextField.getText().isEmpty()) {
				email = modelEmailTextField.getText();
			}
			else {
				modelErrorLabel.setText("Error : Manufacturer email is empty.");
				throw new Exception("");
			}
			
		

			
		switch (modelAlgorithmChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid algorithm selection!");
			modelErrorLabel.setText("Error : Invalid value for Algorithm.");
			throw new Exception("");
		case 0 : //SHA1withDSA
			keyAlgorithm = "DSA";
			break;
		case 1 : //SHA1withRSA
			keyAlgorithm = "RSA";
			break;
		default:
			break;
		}

		switch (modelKeySizeChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid key size selection!");
			modelErrorLabel.setText("Error : Invalid value for Key Size.");
			throw new Exception("");
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
			csrFileName = modelOutputFileChooserText.getText();
		}
		else {
			modelErrorLabel.setText("Error : Output file field is empty.");
			throw new Exception("");
		}
		
		String dn = "CN="+commonName+" O="+organization+" email="+email+" ST="+state+" C="+country;
		System.out.println("Distinguished Name :" + dn);
		System.out.println("Algorithm: " + keyAlgorithm);
		System.out.println("Key Size: " +keySize);
		//System.out.println("Days of validity : " + validity);
		
        
		X500Name x500Name = new X500Name(
				commonName,               // CN
                email,               // OU
                organization,          // O
                "",          // L
                state,               // S
                country); 
		
			CSRRequest csrRequest = new CSRRequest();
			PKCS10 pkcs10 = csrRequest.generatePKCS10(keyAlgorithm, keySize, x500Name,csrFileName,"","");
			if (pkcs10!=null) 
				{System.out.println("Certificate Request Generated");
				modelErrorLabel.setText("Msg: Certification Signing Request Created.");
				}
			else System.err.println("Certificate Request Generation Failed.");

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	@FXML protected void handleDeviceModelDemoButtonAction(ActionEvent event){
		modelOutputFileChooserText.setText("N900.csr");
		modelValidDaysTextField.setText("30");
		modelDeviceNameTextField.setText("N-900");
		modelManufacturerTextField.setText("johnson&johnson");
		modelEmailTextField.setText("jnj_company@outlook.com");
		modelAlgorithmChoiceBox.getSelectionModel().select(0);
		modelKeySizeChoiceBox.getSelectionModel().select(0);
		modelStateOrProvenceChoiceBox.getSelectionModel().select(0);
		modelCountryChoiceBox.getSelectionModel().select(0);
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
	
	
	
	// Device Instance Tab
	@FXML protected TextField instanceOutputFileChooserText;
	@FXML protected TextField instanceRootCertFileChooserText;
	@FXML protected TextField instanceMfgCertFileChooserText;
	@FXML protected TextField instanceDevTypeCertFileChooserText;
	@FXML protected Button generateInstanceButton;
	@FXML protected ChoiceBox instanceAlgorithmChoiceBox;
	@FXML protected ChoiceBox instanceKeySizeChoiceBox;
	@FXML protected TextField instanceValidDaysTextField;
	@FXML protected TextField instanceIdTextField;
	@FXML protected Label instanceSignErrorLabel;
	
	
	
	///////////////////////////////////////////////////////////////////////
	//        Device Instance Tab Event Handlers
	///////////////////////////////////////////////////////////////////////
	@FXML protected CheckBox rootinstcheck;
	@FXML protected CheckBox manfinstcheck;
	@FXML protected CheckBox deviceinstcheck;

	
	@FXML protected void handleInstanceGenerateButtonAction(ActionEvent event) throws Exception {
		//checkModelSignValidityForInstance();
		
		String cerFileName = "";
		String outputFileName = "";
		String caCertFileName ="";
		String manfCertFileName = "";
		String validDays = "";
		String instanceId = "";
		String keyAlgorithm ="";
		String keySize ="";
		
		if (!instanceRootCertFileChooserText.getText().isEmpty()) {
			caCertFileName = instanceRootCertFileChooserText.getText();
		}
		else {
			instanceSignErrorLabel.setText("Error : Root Certificate field is empty.");
			throw new Exception("");
		}	
		
		if (!instanceMfgCertFileChooserText.getText().isEmpty()) {
			manfCertFileName = instanceMfgCertFileChooserText.getText();
		}
		else {
			instanceSignErrorLabel.setText("Error : Manufacturer Certificate field is empty.");
			throw new Exception("");
		}
	
		if (!instanceDevTypeCertFileChooserText.getText().isEmpty()) {
			cerFileName = instanceDevTypeCertFileChooserText.getText();
		}
		else {
			instanceSignErrorLabel.setText("Error : Device model Certificate field is empty.");
			throw new Exception("");
		}
		
		if (!instanceIdTextField.getText().isEmpty()) {
			instanceId = instanceIdTextField.getText();
		}
		else {
			instanceSignErrorLabel.setText("Error : Instance Id field is empty.");
			throw new Exception("");
		}
		switch (instanceAlgorithmChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid algorithm selection!");
			instanceSignErrorLabel.setText("Error : Invalid algorithm selection!");
			throw new Exception("Invalid algorithm selected!");
		case 0 : //SHA1withDSA
			keyAlgorithm = "DSA";
			break;
		case 1 : //SHA1withRSA
			keyAlgorithm = "RSA";
			break;
		default:
			break;
		}

		switch (instanceKeySizeChoiceBox.getSelectionModel().getSelectedIndex()) {
		case -1 :
			System.err.println("Invalid key size selection!");
			instanceSignErrorLabel.setText("Error : Invalid Key selection!");
			throw new Exception("Invalid key size selected!");
		case 0 : //1024
			keySize = "1024";
			break;
		case 1 : //2048
			keySize = "2048";
			break;
		default:
			break;
		}
	
		if (!instanceValidDaysTextField.getText().isEmpty()) {
			validDays = instanceValidDaysTextField.getText();
		}else {
			instanceSignErrorLabel.setText("Error : Days of Validity field is empty.");
			throw new Exception("");
		}
	
		if (!instanceOutputFileChooserText.getText().isEmpty()) {
			outputFileName = instanceOutputFileChooserText.getText();
		}else {
			instanceSignErrorLabel.setText("Error : Output file field is empty.");
			throw new Exception("");
		}
		
	
		checkInstanceValidity();
	
		 ObjectInputStream in = new ObjectInputStream(new FileInputStream(instanceDevTypeCertFileChooserText.getText()));
		    List<byte[]> byteList = (List<byte[]>) in.readObject();
		    CertificateFactory cf = CertificateFactory.getInstance("X.509");
		    InputStream is = new ByteArrayInputStream(byteList.get(0));
			Collection c = cf.generateCertificates(is);
			Iterator i = c.iterator();
			 X509Certificate x509deviceModel_1=null;
			 while (i.hasNext()) {
				 x509deviceModel_1 = (X509Certificate)i.next();
			 }
		 
		 String dn = "CN="+instanceId;
		
		CreateX509Certificate x509Certificate = new CreateX509Certificate();
		X509Certificate instanceCertificate = x509Certificate.generateCertificate(dn,validDays, keyAlgorithm, x509deviceModel_1);
		FileOutputStream out = new FileOutputStream(outputFileName);
		BASE64Encoder encoder = new BASE64Encoder();
		out.write(X509Factory.BEGIN_CERT.getBytes());
		out.write('\n');
	    encoder.encodeBuffer(instanceCertificate.getEncoded(), out);
	    out.write(X509Factory.END_CERT.getBytes());
	    
	    instanceSignErrorLabel.setText("Msg : Device Instance Certificate Created.");
}

	@FXML protected void handleDeviceInstanceDemoButtonAction(ActionEvent event) throws Exception{
		// Device Instance Tab
		instanceOutputFileChooserText.setText("DevInstance.cer");
		instanceRootCertFileChooserText.setText("CACertificate.cer");
		instanceMfgCertFileChooserText.setText("manf_johnson.cer");
		instanceIdTextField.setText("910XCSP221");
		instanceDevTypeCertFileChooserText.setText("N900.cer");
		instanceAlgorithmChoiceBox.getSelectionModel().select(0);
		instanceKeySizeChoiceBox.getSelectionModel().select(0);
		instanceValidDaysTextField.setText("30");
		checkInstanceValidity();
		
	}
	
	@FXML protected void handleRootCertDialogButtonAction(ActionEvent event) throws FileNotFoundException, CertificateException {
		System.out.println("Called");
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceRootCertFileChooserText.setText(f.getName());
		if(instanceRootCertFileChooserTextValidity())
		rootinstcheck.setSelected(true);
	}
	
	@FXML protected void handleMfgCertDialogButtonAction(ActionEvent event) throws Exception  {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceMfgCertFileChooserText.setText(f.getName());
		
		if(instanceMfgCertFileChooserTextValidity())
			manfinstcheck.setSelected(true);
	}
	
	@FXML protected void handleDevTypeCertDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceDevTypeCertFileChooserText.setText(f.getName());
		if(instanceDevTypeCertFileChooserTextValidity())
			deviceinstcheck.setSelected(true);
	}
	
	@FXML protected void handleInstanceFileDialogButtonAction(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		instanceOutputFileChooserText.setText(f.getName());
	//	checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceValidDaysTextFieldAction(ActionEvent event) {
	//	checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceKeySizeChoiceBoxMouseExit(MouseEvent event) {
	//	checkInstanceValidity();
	}
	
	@FXML protected void handleInstanceAlgorithmChoiceBoxMouseExit(MouseEvent event) {
	//	checkInstanceValidity();
	}
	
	/* This is a method that should be called whenever a UI event occurs */
	protected void checkInstanceValidity() throws Exception {
		/* Make sure all required fields are filled out */
		boolean validity = 
				instanceRootCertFileChooserTextValidity() &&
				instanceMfgCertFileChooserTextValidity() &&
				instanceDevTypeCertFileChooserTextValidity() &&
				otherInstanceValidityChecks();
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
		if (!(t.endsWith(".crt") || t.endsWith(".cer") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		validity = true;
		
		return validity;
	}
	
	private boolean instanceRootCertFileChooserTextValidity() throws FileNotFoundException, CertificateException
	{
		String t = instanceRootCertFileChooserText.getText();
		boolean validity = false;
		
		if (t.isEmpty()) return validity;
		if (!new File(t).exists()) {
			//file with path t does not exist.
			return validity;
		}
		if (!(t.endsWith(".crt") || t.endsWith(".cer") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//TODO: maybe do more checks here??
		rootinstcheck.setSelected(false);
		FileInputStream fis = new FileInputStream(instanceRootCertFileChooserText.getText());
		
		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 Collection c = cf.generateCertificates(fis);
		 Iterator i = c.iterator();
		 X509Certificate x509certificateRoot=null;
		 while (i.hasNext()) {
			 x509certificateRoot = (X509Certificate)i.next();
		 }
		 
		 VerifyCertificate verifyCertificate = new VerifyCertificate();
		 if(verifyCertificate.checkRootCA(x509certificateRoot)){
			 validity = true;
		 }
		 
		return validity;
	}

	private boolean instanceMfgCertFileChooserTextValidity() throws Exception
	{
		String t = instanceMfgCertFileChooserText.getText();
		boolean validity = false;
		
		if (t.isEmpty()) return validity;
		if (!new File(t).exists()) {
			//file with path t does not exist.
			return validity;
		}
		if (!(t.endsWith(".crt") ||t.endsWith(".cer") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		//rootinstcheck.setSelected(false);
		manfinstcheck.setSelected(false);
		FileInputStream fis = new FileInputStream(instanceRootCertFileChooserText.getText());
		
		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 Collection c = cf.generateCertificates(fis);
		 Iterator i = c.iterator();
		 X509Certificate x509certificateRoot=null;
		 while (i.hasNext()) {
			 x509certificateRoot = (X509Certificate)i.next();
		 }
		 
		 fis = new FileInputStream(instanceMfgCertFileChooserText.getText());
		 cf = CertificateFactory.getInstance("X.509");
		 Collection c1 = cf.generateCertificates(fis);
		 i = c1.iterator();
		 X509Certificate manf=null;
		 while (i.hasNext()) {
		   manf = (X509Certificate)i.next();
		 }
		 
		 Collection<X509Certificate> collectionX509CertificateChain = new ArrayList<X509Certificate>();
		 collectionX509CertificateChain.add(x509certificateRoot);
		 collectionX509CertificateChain.add(manf);
		 
		 VerifyCertificate verifyCert = new VerifyCertificate();
		 int value = verifyCert.verify(x509certificateRoot, collectionX509CertificateChain);
		 
		 if(value == 1){
			 modelSignErrorLabel.setText("Error : Root Certificate invalid.");
				throw new Exception("");
		 }
		 
		 if (value == 0){
			 rootinstcheck.setSelected(true);
			 manfinstcheck.setSelected(true);
		 }
		 else if(value == 2){
			 rootinstcheck.setSelected(true);
		 }
		 
	
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
		if (!(t.endsWith(".crt") ||t.endsWith(".cer") || t.endsWith(".pem") || t.endsWith(".der"))) {
			return validity;
		}
		
		deviceinstcheck.setSelected(false);
		validity = checkModelSignValidityForInstance();
		System.out.println(validity);
		return validity;
	}
	
	private boolean checkModelSignValidityForInstance() {
		//TODO: write me!
		if(!instanceRootCertFileChooserText.getText().isEmpty() 
				&& !instanceMfgCertFileChooserText.getText().isEmpty()
					&& !instanceDevTypeCertFileChooserText.getText().isEmpty()){
			
			//Read CA Certificate
			FileInputStream fis;
			try {
				fis = new FileInputStream(instanceRootCertFileChooserText.getText());
			
			 CertificateFactory cf = CertificateFactory.getInstance("X.509");
			 Collection c = cf.generateCertificates(fis);
			 Iterator i = c.iterator();
			 X509Certificate x509certificateRoot=null;
			 while (i.hasNext()) {
				 x509certificateRoot = (X509Certificate)i.next();
			 }
			 
			 //Read Manufacturer Certificate.
			fis = new FileInputStream(instanceMfgCertFileChooserText.getText());
			 cf = CertificateFactory.getInstance("X.509");
			 Collection c1 = cf.generateCertificates(fis);
			 i = c1.iterator();
			 X509Certificate manf=null;
			 while (i.hasNext()) {
			   manf = (X509Certificate)i.next();
			 }
			 
			 ObjectInputStream in = new ObjectInputStream(new FileInputStream(instanceDevTypeCertFileChooserText.getText()));
			    List<byte[]> byteList = (List<byte[]>) in.readObject();
			    cf = CertificateFactory.getInstance("X.509");
			    InputStream is = new ByteArrayInputStream(byteList.get(0));
				c = cf.generateCertificates(is);
				i = c.iterator();
				 X509Certificate x509deviceModel_1=null;
				 while (i.hasNext()) {
					 x509deviceModel_1 = (X509Certificate)i.next();
				 }
				 
				 cf = CertificateFactory.getInstance("X.509");
				 is = new ByteArrayInputStream(byteList.get(1));
					c = cf.generateCertificates(is);
					i = c.iterator();
					 X509Certificate x509deviceModel_2=null;
					 while (i.hasNext()) {
						 x509deviceModel_2 = (X509Certificate)i.next();
					 }
			 
			 
			 Collection<X509Certificate> collectionX509CertificateChain = new ArrayList<X509Certificate>();
			 collectionX509CertificateChain.add(x509certificateRoot);
			 collectionX509CertificateChain.add(manf);
			 collectionX509CertificateChain.add(x509deviceModel_1);
			 collectionX509CertificateChain.add(x509deviceModel_2);
			 
			 VerifyCertificate verifyCert = new VerifyCertificate();
			 int value = verifyCert.verify(x509certificateRoot, collectionX509CertificateChain);
			 
			 if (value == 0){
				 rootinstcheck.setSelected(true);
				 manfinstcheck.setSelected(true);
				 deviceinstcheck.setSelected(true);
			 }
			 else if(value == 2){
				 rootinstcheck.setSelected(true);
			 }
			 else if(value == 3){
				 rootinstcheck.setSelected(true);
				 manfinstcheck.setSelected(true);
			 }
			 
			 return true;
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return false;
	}
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	//        Device Model Certificate Signing Event Handlers            //
	///////////////////////////////////////////////////////////////////////
	@FXML protected TextField modelSignRootCertFileChooserText;
	@FXML protected TextField modelSignMfgCertFileChooserText;
	@FXML protected TextField modelSignDevTypeCertFileChooserText;
	@FXML protected TextField modelSignOutputFileChooserText;
	@FXML protected TextField modelSignValidDaysTextField;
	@FXML protected Label modelSignErrorLabel;
	@FXML protected CheckBox rootcheck;
	@FXML protected CheckBox manfcheck;
	@FXML protected CheckBox csrcheck;
	
	/*
	 * Need to place a CA configuration file in the directory this command is ran from.
	 */
	@FXML protected void handleModelSignButtonAction(ActionEvent event) {
		String currentDirectory = System.getProperty("user.dir");
		String csrFileName = "";
		String outputFileName = "";
		String caCertFileName ="";
		String manfCertFileName = "";
		String validDays = "";

		try{
			
			if (!modelSignRootCertFileChooserText.getText().isEmpty()) {
				caCertFileName = modelSignRootCertFileChooserText.getText();
			}
			else {
				modelSignErrorLabel.setText("Error : Root Certificate field is empty.");
				throw new Exception("");
			}	
			
			if (!modelSignMfgCertFileChooserText.getText().isEmpty()) {
				manfCertFileName = modelSignMfgCertFileChooserText.getText();
			}
			else {
				modelSignErrorLabel.setText("Error : Manufacturer Certificate field is empty.");
				throw new Exception("");
			}
		
			if (!modelSignDevTypeCertFileChooserText.getText().isEmpty()) {
				csrFileName = modelSignDevTypeCertFileChooserText.getText();
			}
			else {
				modelSignErrorLabel.setText("Error : Device model request field is empty.");
				throw new Exception("");
			}
		
			if (!modelSignValidDaysTextField.getText().isEmpty()) {
				validDays = modelSignValidDaysTextField.getText();
			}
		
			if (!modelSignOutputFileChooserText.getText().isEmpty()) {
				outputFileName = modelSignOutputFileChooserText.getText();
			}
		
		FileInputStream fis;
	
		fis = new FileInputStream(csrFileName);
		
        byte[] buffer = new byte[4096];
        ByteArrayOutputStream ous = new ByteArrayOutputStream();
        int read = 0;
        while ( (read = fis.read(buffer)) != -1 ) {
            ous.write(buffer, 0, read);
        }
        ous.close();
        fis.close();
 
        String s=new String(buffer);
        String certificateDataString = removeCSRHeadersAndFooters(s); // remove headers and footers

        System.out.println(certificateDataString);
        
        byte[] derByteArray = DatatypeConverter.parseBase64Binary(certificateDataString); // PEM -> DER
        PKCS10 newpk=new PKCS10(derByteArray);
        
        HandleCSRRequest handleCSRRequest = new HandleCSRRequest();
		handleCSRRequest.handleRequest(newpk, "tempManf",manfCertFileName);
		handleCSRRequest.handleRequest(newpk, "tempCa","CA");
		
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		checkModelSignValidity();
		
		
			try {
				List<byte[]> list = new ArrayList<byte[]>();	
				Path path = Paths.get("tempManf.cer");
				 list.add(Files.readAllBytes(path));
				 Files.delete(path);
				// list.add("/n/n".getBytes());
				 	path = Paths.get("tempCa.cer");
				 list.add(Files.readAllBytes(path));
				 Files.delete(path);
				 
				 
				 
				 ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(outputFileName));
				    out.writeObject(list);
				    out.close();
				    
				    modelSignErrorLabel.setText("Msg : Device Model Certificate Created.");
				 
				    ObjectInputStream in = new ObjectInputStream(new FileInputStream(outputFileName));
				    List<byte[]> byteList = (List<byte[]>) in.readObject();

				    //if you want to add to list you will need to add to byteList and write it again
				    System.out.println("ByteList Size :" + byteList.size());
				    for (byte[] bytes : byteList) {
				        System.out.println(new String(bytes));
				    }
			 
		 
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
	}

	
	
	@FXML protected void handleSignDeviceDemoButtonAction(ActionEvent event){
		modelSignOutputFileChooserText.setText("N900.cer");
		modelSignRootCertFileChooserText.setText("CACertificate.cer");
		modelSignMfgCertFileChooserText.setText("manf_johnson.cer");
		modelSignDevTypeCertFileChooserText.setText("N900.csr");
		modelSignValidDaysTextField.setText("30");
		checkModelSignValidity();
	}
	
	
	@FXML protected void handleModelSignRootCertDialogButtonAction(ActionEvent event) throws Exception {
		modelSignErrorLabel.setText("");
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Select a Root Certificate File.");
		File f = fileChooser.showOpenDialog(stage);
		if (f == null) { System.err.println("Null File."); }
		else {
			modelSignRootCertFileChooserText.setText(f.getName());
			boolean result = checkCertificatevalidity("CA");
			if(result){
				rootcheck.setSelected(true);
			}
			else{
				modelSignErrorLabel.setText("Error : Root Certificate invalid.");
				throw new Exception("");
			}
		}
	}
	
	@FXML protected void handleModelSignMfgCertDialogButtonAction(ActionEvent event) throws Exception {
		modelSignErrorLabel.setText("");
		if (modelSignRootCertFileChooserText.getText().isEmpty()) {
			modelSignErrorLabel.setText("Error : Root Certificate field is empty.");
			throw new Exception("");
		}	
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		modelSignMfgCertFileChooserText.setText(f.getName());
		boolean result = checkCertificatevalidity("Manf");
		if(result){
			rootcheck.setSelected(true);
		}
		else{
			modelSignErrorLabel.setText("Error : Manufacturer Certificate invalid.");
			throw new Exception("");
		}
	}
	
	@FXML protected void handleModelSignDevTypeCertDialogButtonAction(ActionEvent event) throws Exception {
		modelSignErrorLabel.setText("");
		FileChooser fileChooser = new FileChooser();
		File f = fileChooser.showOpenDialog(stage);
		modelSignDevTypeCertFileChooserText.setText(f.getName());
		boolean result = checkCertificatevalidity("");
		if(result){
			csrcheck.setSelected(true);
		}
		else{
			modelSignErrorLabel.setText("Error : Device Model Certficate Request invalid.");
			throw new Exception("");
		}
	}
	
	@FXML protected void handleModelSignFileDialogButtonAction(ActionEvent event) {
		DirectoryChooser fileChooser = new DirectoryChooser();
		File f = fileChooser.showDialog(stage);
		String s = f.getPath();
	}
	
	/**
     * Takes in a CSR/p10 as a string and removes the headers and footers of the request string.
     * 
     * @param inString a CSR string
     * @return a CSR String stripped of the text headers and footers
     */
    public static String removeCSRHeadersAndFooters(String inString)
    {
        inString = inString.replace("-----BEGIN NEW CERTIFICATE REQUEST-----" + "\n", "");
        inString = inString.replace("\n" + "-----END NEW CERTIFICATE REQUEST-----" + "\n", "");
      return inString;
    }
    
    
    public boolean checkCertificatevalidity(String certName){
    	try{
    		
	    	if(certName.equals("CA")){
	    		rootcheck.setSelected(false);
	    		FileInputStream fis = new FileInputStream(modelSignRootCertFileChooserText.getText());
				
				 CertificateFactory cf = CertificateFactory.getInstance("X.509");
				 Collection c = cf.generateCertificates(fis);
				 Iterator i = c.iterator();
				 X509Certificate x509certificateRoot=null;
				 while (i.hasNext()) {
					 x509certificateRoot = (X509Certificate)i.next();
				 }
				 
				 VerifyCertificate verifyCertificate = new VerifyCertificate();
				 if(verifyCertificate.checkRootCA(x509certificateRoot)){
					 return true;
				 }
	    	}
	    	else if(certName.equals("Manf")){
	    		rootcheck.setSelected(false);
	    		manfcheck.setSelected(false);
	    		FileInputStream fis = new FileInputStream(modelSignRootCertFileChooserText.getText());
				
				 CertificateFactory cf = CertificateFactory.getInstance("X.509");
				 Collection c = cf.generateCertificates(fis);
				 Iterator i = c.iterator();
				 X509Certificate x509certificateRoot=null;
				 while (i.hasNext()) {
					 x509certificateRoot = (X509Certificate)i.next();
				 }
				 
				 fis = new FileInputStream(modelSignMfgCertFileChooserText.getText());
				 cf = CertificateFactory.getInstance("X.509");
				 Collection c1 = cf.generateCertificates(fis);
				 i = c1.iterator();
				 X509Certificate manf=null;
				 while (i.hasNext()) {
				   manf = (X509Certificate)i.next();
				 }
				 
				 Collection<X509Certificate> collectionX509CertificateChain = new ArrayList<X509Certificate>();
				 collectionX509CertificateChain.add(x509certificateRoot);
				 collectionX509CertificateChain.add(manf);
				 
				 VerifyCertificate verifyCert = new VerifyCertificate();
				 int value = verifyCert.verify(x509certificateRoot, collectionX509CertificateChain);
				 
				 if(value == 1){
					 modelSignErrorLabel.setText("Error : Root Certificate invalid.");
						throw new Exception("");
				 }
				 
				 if (value == 0){
					 rootcheck.setSelected(true);
					 manfcheck.setSelected(true);
				 }
				 else if(value == 2){
					 rootcheck.setSelected(true);
				 }
				 
	    		return true;
	    	}
	    	
	    	else{
	    		FileInputStream fis = new FileInputStream(modelSignDevTypeCertFileChooserText.getText());
		        byte[] buffer = new byte[4096];
		        ByteArrayOutputStream ous = new ByteArrayOutputStream();
		        int read = 0;
		        while ( (read = fis.read(buffer)) != -1 ) {
		            ous.write(buffer, 0, read);
		        }
		        ous.close();
		        fis.close();
		 
		        String s=new String(buffer);
		        String certificateDataString = removeCSRHeadersAndFooters(s); // remove headers and footers
		        byte[] derByteArray = DatatypeConverter.parseBase64Binary(certificateDataString); // PEM -> DER
		        PKCS10 newpk=new PKCS10(derByteArray);
		        
		        
		        System.out.println("CSR Info ---");
		        System.out.println(newpk.getSubjectName());
		        if(!newpk.getSubjectName().isEmpty()){
		        	return true;
		        }
	    	}
    	}
    	catch (Exception e){
    		e.printStackTrace();
    	}
    	return false;
    }
	
	@SuppressWarnings("rawtypes")
	private void checkModelSignValidity() {
		//TODO: write me!
		if(!modelSignRootCertFileChooserText.getText().isEmpty() 
				&& !modelSignMfgCertFileChooserText.getText().isEmpty()
					&& !modelSignDevTypeCertFileChooserText.getText().isEmpty()){
			
			//Read CA Certificate
			FileInputStream fis;
			try {
				fis = new FileInputStream(modelSignRootCertFileChooserText.getText());
			
			 CertificateFactory cf = CertificateFactory.getInstance("X.509");
			 Collection c = cf.generateCertificates(fis);
			 Iterator i = c.iterator();
			 X509Certificate x509certificateRoot=null;
			 while (i.hasNext()) {
				 x509certificateRoot = (X509Certificate)i.next();
			 }
			 
			 //Read Manufacturer Certificate.
			fis = new FileInputStream(modelSignMfgCertFileChooserText.getText());
			 cf = CertificateFactory.getInstance("X.509");
			 Collection c1 = cf.generateCertificates(fis);
			 i = c1.iterator();
			 X509Certificate manf=null;
			 while (i.hasNext()) {
			   manf = (X509Certificate)i.next();
			 }
			 
			 //Read CSR request.
			 	fis = new FileInputStream(modelSignDevTypeCertFileChooserText.getText());
		        byte[] buffer = new byte[4096];
		        ByteArrayOutputStream ous = new ByteArrayOutputStream();
		        int read = 0;
		        while ( (read = fis.read(buffer)) != -1 ) {
		            ous.write(buffer, 0, read);
		        }
		        ous.close();
		        fis.close();
		 
		        String s=new String(buffer);
		        String certificateDataString = removeCSRHeadersAndFooters(s); // remove headers and footers
		        byte[] derByteArray = DatatypeConverter.parseBase64Binary(certificateDataString); // PEM -> DER
		        PKCS10 newpk=new PKCS10(derByteArray);
		        
		        boolean flag = false;
		        System.out.println("CSR Info ---");
		        System.out.println(newpk.getSubjectName());
		        if(!newpk.getSubjectName().isEmpty()){
		        	flag =true;
		        }
		        
			 
			 
			 Collection<X509Certificate> collectionX509CertificateChain = new ArrayList<X509Certificate>();
			 collectionX509CertificateChain.add(x509certificateRoot);
			 collectionX509CertificateChain.add(manf);
			 
			 VerifyCertificate verifyCert = new VerifyCertificate();
			 int value = verifyCert.verify(x509certificateRoot, collectionX509CertificateChain);
			 if (value == 0){
				 rootcheck.setSelected(true);
				 manfcheck.setSelected(true);
				 if(flag == true) csrcheck.setSelected(true);
			 }
			 else if(value == 2){
				 rootcheck.setSelected(true);
				 if(flag == true) csrcheck.setSelected(true);
			 }
	
			 
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}
	
	private String executeCommand(String command) {
		 
		StringBuffer output = new StringBuffer();
 
		Process p;
		try {
			System.out.println(command);
			p = Runtime.getRuntime().exec(command);
			BufferedReader reader = 
                            new BufferedReader(new InputStreamReader(p.getErrorStream()));
 
                        String line = "";			
			while ((line = reader.readLine())!= null) {
				output.append(line + "\n");
			}
			p.waitFor();
 
		} catch (Exception e) {
			e.printStackTrace();
		}
 
		return output.toString();
 
	}
}
