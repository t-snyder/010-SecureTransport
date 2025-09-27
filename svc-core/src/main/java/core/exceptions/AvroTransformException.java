package core.exceptions;

public class AvroTransformException extends Exception
{
  private static final long serialVersionUID = 2908990171511790800L;

  
  public AvroTransformException( String msg ) 
  {
    super( msg );
  }

  public AvroTransformException( Exception e )
  {
    super( e );
  }
}
