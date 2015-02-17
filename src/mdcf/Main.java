package mdcf;

import java.io.IOException;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws IOException {
		FXMLLoader loader = new FXMLLoader(getClass().getResource("Certificate-GUI-mockup.fxml"));
		//Parent root = FXMLLoader.load(getClass().getResource("Certificate-GUI-mockup.fxml"));
		Parent root = (Parent)loader.load();
		GuiController controller = (GuiController) loader.getController();
		controller.setStage(primaryStage);
		
		Scene scene = new Scene(root);
		primaryStage.setScene(scene);
		primaryStage.setTitle("MDCF Certificate Tool");
		primaryStage.show();
	}

	public static void main(String[] args) {
		launch(args);
	}
}
