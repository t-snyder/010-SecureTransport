package core.exceptions;

public class NotFoundException extends Exception
{
  private static final long serialVersionUID = 4757120132833816243L;

  public NotFoundException( String msg )
  {
    super( msg );
  }
}
