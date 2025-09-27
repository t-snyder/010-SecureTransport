package core.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class B64Handler
{
  public static String decodeB64( String val )
  {
    if( val == null )
      return null;
    return new String( Base64.getDecoder().decode( val ), StandardCharsets.UTF_8 );
  }

  public static String encodeB64( String val )
  {
    if( val == null )
      return null;
    return Base64.getEncoder().encodeToString( val.getBytes( StandardCharsets.UTF_8 ) );
  }

}
