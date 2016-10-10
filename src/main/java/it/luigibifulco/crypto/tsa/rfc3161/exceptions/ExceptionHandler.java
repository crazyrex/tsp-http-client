package it.luigibifulco.crypto.tsa.rfc3161.exceptions;

/**
 * 
 * @author Luigi Bifulco
 *
 */
import java.lang.Thread.UncaughtExceptionHandler;

public class ExceptionHandler implements UncaughtExceptionHandler {

	public void uncaughtException(final Thread p_thread, final Throwable p_throwable) {
		System.out.println(p_throwable.getMessage());
		p_throwable.printStackTrace(); // TODO
	}

}
