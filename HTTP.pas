{
    websniffer - HTTP.pas (Ver1.1) (HTTP connection analysis)
    Copyright (C) 2005 Josef Schützenberger

    websniffer is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    websniffer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with websniffer; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
}
unit HTTP;

interface
uses
  Classes,PcapNet,buffer;
type
 THTTPContext=class
 private
   procedure Reset;
 public
   FHasFoundGet,FHasFoundHTTPReply,FChunked,FDone,FIsGZIP:Boolean;
   FHTTPReplyCode,FContentLengthOrig,FContentLength,FChunkLen:integer;
   FRangeFrom,FRangeTo,FRangeTotal:integer;
   FFileName,FHost,FChunkLenStrPart:String;
   FQuota:Single;                             
   FOwner:TList;
   constructor create(Owner:TList);
   function onRequestStream(buf:PChar;Len:integer;var replybuf:TBuf):Pchar;
   function onReplyData(buf:PChar;Len:integer;const replybuf:TBuf):Pchar;
   procedure WriteFile(const replybuf:TBuf);
 end;
implementation
uses StrUtils,SysUtils,conitem;
constructor THTTPContext.create(Owner:TList);
begin
  FHasFoundGet:=false;
  FHasFoundHTTPReply:=false;
  FChunkLen:=-1;
  FDone:=false;
  FContentLengthOrig:=-1;
  FOwner:=Owner;
end;
function THTTPContext.onRequestStream(buf:PChar;Len:integer;var replybuf:TBuf):Pchar;
var s,g:String;i,k:integer;
begin
  result:=SearchBuf(Buf,Len, 0, 0,#13+#10+#13+#10,[soDown]);
  if result<>nil then begin
    result:=result+4;
    s:=URLDecode(buf,result-buf);
    if Pos('GET',s)=1 then
    begin
      FHasFoundGet:=true;
      i:=PosEx(' ',s,5);
      FFileName:=copy(s,5,i-5);
{  if pos('sb7-040805-SQUID' ,ffilename) >0 then
  s:=s;
   if pos('milkyway' ,ffilename) >0 then
  s:=s;}
      i:=Pos('Host: ',s);
      k:=PosEx(#13#10,s,i);
      if (i>0) and (k>i) then FHost:=Copy(s,i+6,k-i-6);
      FQuota:=0;
//             TConlist(FOwner).OnPaMessage('-----ContentLength '+FHost+FFileName,2);
      i:=Pos('Accept-Language: ',s);
      k:=PosEx(#13#10,s,i);
      if i>0 then
      begin
          i:=PosEx(';',s,i);
          if (i>0) and (i<k) then i:=PosEx('q=',s,i);
          if (i>0) and (i<k) then
          begin
            g:=Copy(s,i+2,k-i-2);
            Val(g,FQuota,i);
            if i>0 then FQuota:=0;
          end;
      end;
      FRangeFrom:=0;
      i:=Pos('Range: bytes=',s);
      if i>0 then
      begin
        k:=PosEx('-',s,i);
        g:=Copy(s,i+13,k-i-13);
        if TryStrToInt(g,FRangeFrom)then
        begin
          if (FRangeFrom>0) and (replybuf.DataLen<>cardinal(FRangeFrom)) then
          if TConlist(FOwner).ExchangeBuffer(FHost,FFileName,FRangeFrom,replybuf) then
          begin
            replybuf.DataLen:=FRangeFrom;
            FRangeFrom:=0;
          end else
          begin
            TConlist(FOwner).OnPaMessage('Partial Content File '+FHost+FFileName,2);
          end;
        end else Assert(false,'Range error '+FHost+FFileName);
      end;
    end;
  end;
end;

function GetChunkLen(var buf:PChar;Len:integer):integer;
var i:integer;s:string;start:Boolean;
begin
  s:='$';start:=false;
  for i:=0 to Len-1 do
  begin
    if (buf[i]>='0') then begin s:=s+buf[i]; start:=true; end;
    if start and (buf[i]<'0')  then break;
  end;
  if TryStrToint(s,result) then
  begin
    buf:=buf+i+2;
  end else begin
    result:=-1;
    buf:=buf+Len;
  end;
end;

function GetChunkLenStr(buf:String):String;
var i,k,len:integer;
begin
    len:=Length(buf);
    result:='';k:=1;
    if len=0 then  exit;
    if buf[k]<>#13 then exit;
    result:=buf[k];
    if k>=Len then exit;
    inc(k);
    if buf[k]<>#10 then exit;
    result:=result+buf[k];
    if k>=Len then exit;
    for i:=k+1 to len do begin
      if (buf[i]<'0') then break;
      result:=result+buf[i];
    end;
    k:=i;
    if buf[k]<>#13 then exit;
    result:=result+buf[k];
    if k>=Len then exit;
    inc(k);
    if buf[k]<>#10 then exit;
    result:=result+buf[k];
end;

function StrToLength(S:string):integer;
begin
  result:=-1;
  if (length(s)<4) or (s[length(s)]<>#10) then exit;
  s:='$'+copy(s,3,length(s)-4);
  if not TryStrToint(s,result) then result:=-1;
end;

function THTTPContext.onReplyData(buf:PChar;Len:integer;const replybuf:TBuf):Pchar;
var s,cont:String;i,k,j,CLen:integer;P,T:PChar;
begin
  result:=nil;
  if not FHasFoundGet then
  begin
    exit;
  end;
  P:=buf;
//   if pos('milkyway.jpg' ,ffilename) >0 then
//  s:=s;
  if not FHasFoundHTTPReply then
  begin
    P:=SearchBuf(Buf,Len, 0, 0,#13+#10+#13+#10,[soDown]);
    if P<>nil then
    begin
      P:=P+4;
      s:=URLDecode(buf,P-buf);
      if Pos('HTTP',s)=1 then
      begin
        FHasFoundHTTPReply:=true;
        i:=Pos(' ',s);
        if i>0 then TryStrToint(Copy(s,i+1,3),FHTTPReplyCode);
        i:=Pos('Content-Length: ',s);
        if i=0 then i:=Pos('Content-length: ',s);
        k:=PosEx(#13#10,s,i);
        if (i>0) and (k>i) then TryStrToint(Copy(s,i+16,k-i-16),FContentLengthOrig);
        FContentLength:=FContentLengthOrig;
        i:=Pos('Content-Encoding: ',s);
        k:=PosEx(#13#10,s,i);
        FIsGZIP:=(i>0) and (k>i) and (Copy(s,i+18,k-i-18)='gzip');
        i:=Pos('Transfer-Encoding: ',s);
        k:=PosEx(#13#10,s,i);
        if (i>0) and (k>i) then cont:=Copy(s,i+19,k-i-19);
        if cont='chunked' then
        begin
          FChunked:=true;
          FChunkLen:=GetChunkLen(P,Len-(P-buf));
          if  FChunkLen=400 then
          begin
            FDone:=FDone;
           end;
          if  FChunkLen<0 then
          begin
            FDone:=true;
            TConlist(FOwner).OnPaMessage('FChunkLen-error',2);
          end;
        end;
        if  FHTTPReplyCode=206 then    //Partial Content
        begin
          i:=Pos('Content-Range: bytes ',s);
          k:=PosEx(#13#10,s,i);
          if i>0 then
          begin
            j:=PosEx('-',s,i+9);
            i:=PosEx('/',s,i);
            cont:=Copy(s,j+1,i-j-1);
            TryStrToint(cont,FRangeTo);
            i:=PosEx('/',s,i);
            cont:=Copy(s,i+1,k-i-1);
            TryStrToint(cont,FRangeTotal);
            assert(FRangeTotal>0,'FRangeTotal-error');
          end;
        end;  //if  FHTTPReplyCode=206
      end;
    end;
  end; //if  not FHasFoundHTTPReply
  if not FHasFoundHTTPReply then exit;
  if Fchunked and (FChunkLen>-1) and not FDone then begin
    T:=P;CLen:=0;
    while ((FChunkLen)< Len-(T-buf)) and not FDone do
    begin
      T:=T+FChunkLen+CLen;
      s:=FChunkLenStrPart;
      k:=Len-(T-buf)-1;
      if k<=0 then break;//Error
      if k>10 then k:=10;
      for i:=0 to k do s:=s+T[i];
      s:=GetChunkLenStr(s);
      FChunkLen:=StrToLength(s);
      if FChunkLen=0 then FDone:=true;
      CLen:=length(s)-length(FChunkLenStrPart);
      if FChunkLen<0 then FChunkLenStrPart:=s else FChunkLenStrPart:='';
      if FDone then CLen:=CLen+2;
      Move(P^, (P+CLen)^, T-P);
      P:=P+CLen;
      if FChunkLen < 0 then break;
    end;
    FChunkLen:=FChunkLen-(Len-(T-buf)-Clen);
    if FChunkLen<0 then FChunkLen:=0;
    if  FChunkLen=0 then FDone:=true;
  end;
  if FContentLengthOrig>0 then
  begin
    FContentLength:=FContentLength-(Len-(P-buf));
    if FContentLength<0 then
            TConlist(FOwner).OnPaMessage('Error ContentLength '+FHost+FFileName,2);
    Assert( FContentLength>=0,'Error ContentLength');
    if  FContentLength<=0 then FDone:=true;
  end;
  result:=P;
  if  (FHTTPReplyCode=304) or (FHTTPReplyCode=404)       //304 Not Modified    404 Not Found
   or (FHTTPReplyCode=302) or (FHTTPReplyCode=301) then // 302 Moved Temporarily  301 Moved Permanently
  begin
    if Assigned(TConlist(FOwner).FOnHTTPReplyCode) then
      TConlist(FOwner).FOnHTTPReplyCode(FFilename,FHost,FHTTPReplyCode);
    Reset;
    replybuf.DataLen:=0;
    result:=nil;
  end;
end;

procedure THTTPContext.Reset;
begin
  FHasFoundGet:=false;
  FHasFoundHTTPReply:=false;
  FDone:=false;
  FChunkLen:=-1;
  FChunked:=false;
  FFileName:='';
  FContentLengthOrig:=-1;
  FIsGZIP:=false;
  FRangeFrom:=0;
  FRangeTo:=0;
  FRangeTotal:=0;
end;

procedure THTTPContext.WriteFile(const replybuf:TBuf);
var fs1 : TFileStream;dir,FileName:String;
begin
  fs1:=nil;
  if replybuf.DataLen=0 then
  begin
    Reset;
    exit;
  end;
  if Pos(':',FHost)=0 then FileName:=FHost+FFileName else
     FileName:=copy(FHost,1,Pos(':',FHost)-1)+FFileName;
  FileName:=AnsiReplaceText(FileName,'/','\');
  if Pos('?',FileName)>0 then FileName:=copy(FileName,1,Pos('?',FileName)-1);
  if  ExtractFileName(FileName)='' then
    FileName:=IncludeTrailingPathDelimiter(Filename)+'index.htm';
  if ExtractFileExt(FileName)='' then Filename:=Filename+'.htm';
  FileName:=AnsiReplaceText(FileName,'*','_');
  if FIsGZIP then FileName:=ChangeFileExt(FileName,'.zip');
  TConlist(FOwner).OnFileSave(Filename,FHost,replybuf.DataLen);
  if Filename<>''then
  begin
    dir:=ExtractFileDir(''+FileName);
    try
      ForceDirectories(Dir);
      if  FHTTPReplyCode=206 then    //Partial Content
      begin
        if FileExists(FileName) then begin
          fs1 := TFileStream.Create(FileName,fmOpenReadWrite);
          if fs1.Size>=FRangeFrom then
          begin                                
            fs1.Position:=FRangeFrom;
            fs1.WriteBuffer(replybuf.Buffer^,replybuf.DataLen);
          end;
        end else
        begin
          fs1 := TFileStream.Create(FileName, fmCreate or fmOpenReadWrite);
        //  fs1.Position:=FRangeFrom;
          fs1.WriteBuffer(replybuf.Buffer^,replybuf.DataLen);
        end;
      end else
      begin
        fs1 := TFileStream.Create(FileName, fmCreate or fmOpenWrite);
        fs1.WriteBuffer(replybuf.Buffer^,replybuf.DataLen);
      end;
    except
      TConlist(FOwner).OnErrorMsg('Cannot create '+FileName);
    end;
    if fs1 <> nil then fs1.Free;
  end;
  replybuf.DataLen:=0;
  Reset;
end;

end.
