package core.utils;

import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.apache.avro.Schema;
import org.apache.avro.generic.GenericArray;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.util.Utf8;

public class AvroUtil
{

  public int getInt( GenericRecord result, String attrName )
  {
    Integer i = (Integer)result.get( attrName );
    
    if( i != null )
      return i.intValue();
    
    return -1;
  }

  public long getLong( GenericRecord result, String attrName )
  {
    Long l = (Long)result.get( attrName );
    
    if( l != null )
      return l.longValue();
    
    return -1;
  }

  public byte[] getByteArray( GenericRecord result, String attrName )
  {
    byte[] returnVal = null;
    
    ByteBuffer theBuf  = (ByteBuffer) result.get( attrName );
    if( theBuf != null )
    {
      ByteBuffer bufCopy = theBuf.duplicate();
      
      // Reset to the beginning of the buffer to ensure we read all data
      bufCopy.rewind();
      
      returnVal = new byte[bufCopy.remaining()];
      bufCopy.get( returnVal, 0, bufCopy.remaining() );
    }
    
    return returnVal;
  }

  public String getString( GenericRecord result, String attrName )
  {
    Utf8 item = (Utf8)result.get( attrName );
    if( item != null )
      return item.toString();
    
    return null;
  }

  public Date getDate( GenericRecord result, String attrName )
  {
    Utf8 item = (Utf8)result.get( attrName );
    if( item != null )
    {
      String dateStr = item.toString();
      DateFormat formatter = new SimpleDateFormat( "dd-MMM-yy" );
      try
      {
        return formatter.parse( dateStr );
      } catch( ParseException e )
        {
          e.printStackTrace();
        }
    }
    
    return null;
  }

  public String dateToString( Date date )
  {
    String dateStr = null;
    
    if( date != null )
    {  
      DateFormat formatter = new SimpleDateFormat( "dd-MMM-yy" ); 
      dateStr = formatter.format( date );
    }
    
    return dateStr;
  }

  public boolean getBoolean( GenericRecord result, String attrName )
  {
    Boolean bool = (Boolean) result.get( attrName );
    if( bool != null )
    {
      return bool.booleanValue();
    }
    
    return false;
  }
 
  public GenericArray<Utf8> stringListToAvro( List<String> theList, Schema schemaElement )
  {
    GenericData.Array<Utf8> stringArray = new GenericData.Array<Utf8>( theList.size(), schemaElement );
     
    if( theList != null )
    {
      for( String listElem : theList )
      {  
        stringArray.add( new Utf8( listElem ));
      }
    }
    
    return stringArray;
  }

  
  public void unMarshallStringList( GenericArray<Utf8> genArr, List<String> theList )
  {
    if( genArr != null )
    {
      for( Utf8 utfStr : genArr )
      {
        theList.add( utfStr.toString() );
      }
    }
  }
}
