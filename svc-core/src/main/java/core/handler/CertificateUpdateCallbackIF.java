package core.handler;

public interface CertificateUpdateCallbackIF
{
  /**
   * Called when certificates are successfully updated
   */
  void onCertificateUpdated();
  
  /**
   * Called when certificate update fails
   * @param error The exception that caused the failure
   */
  void onCertificateUpdateFailed(Exception error);
}
