{
    websniffer - ConItem.pas (TCP connection analysis)
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
unit ConItem;

interface

uses
  Classes,PcapNet,http,buffer;
type
  TConItem =class;

  TPacket1=record
    seq: Cardinal;
    Len:Cardinal;
  end;
  TPacketList1=class
    PacketBuf: TWindowBuf;
    Packets:array of TPacket1;
  public
    constructor Create;
    function AddPacket(seq:cardinal;buf:PChar;Len:cardinal): Boolean;
    function Count: integer;
    function GetPacket(seq:cardinal;var Buf:PChar;var Len:cardinal): boolean;
    procedure Free;
  end;
  TOnSaveFile = procedure(var Filename:String;Host:String;Len:Integer) of object;
  TOnPacketMessage = procedure(const msg:String;const Info:Integer) of object;
  TOnError = procedure(const msg:String) of object;
  TOnHTTPReplyCode = procedure(const Filename:String;Host:String;HTTPReplyCode:Integer) of object;
  TConList = class(TList)
  private
   FOnSaveFile:TOnSaveFile;
   FOnPacketMessage:TOnPacketMessage;
   FOnError:TOnError;
   protected
  public
    FOnHTTPReplyCode:TOnHTTPReplyCode;
    function  ExchangeBuffer(const Host,Filename:String;Range:Cardinal;var Buffer:Tbuf):boolean;
    procedure OnFileSave(var Filename:String;Host:String;Len:Integer);
    procedure OnPaMessage(const msg:String;const Info:Integer);
    procedure OnErrorMsg(const msg:String);
    procedure Free;
  published
    property OnSaveFile: TOnSaveFile read FOnSaveFile write FOnSaveFile;
    property OnHTTPReplyCode: TOnHTTPReplyCode read FOnHTTPReplyCode write FOnHTTPReplyCode;
    property OnPacketMessage: TOnPacketMessage read FOnPacketMessage write FOnPacketMessage;
    property OnError: TOnError read FOnError write FOnError;
  end;
 TConItem =class(TObject)
 private
   PacketList1:TPacketList1;
 public
   lastTime:Integer;
   DestIp: integer;
   SrcIp: integer;
   DestPort: word;
   SrcPort: word;
   ConitemNr:integer;
   reqbuf,replybuf:Tbuf;
   HTTPContext:THTTPContext;
   ReqSeqPosition:cardinal;
   ReplySeqPosition:cardinal;
   CloseOnSave:boolean;
   FOwner:TConList;
   constructor create(ASrcIp,ADestIp:integer;ASrcPort,ADestPort: word;Owner:TConList);
   function onPacket(dir:Integer;IPheader:PIP_header;TCPheader:PTCP_header;TCPPayload:PChar;PayloadLen:cardinal):boolean;
   destructor free;
 end;

implementation
uses StrUtils,sysutils;

constructor TPacketList1.Create;
var i:integer;
begin
  inherited create;
  PacketBuf:=TWindowBuf.Create;
  SetLength(Packets, 5);
  for i:=0 to High(Packets)-0 do Packets[i].Len:=0;
end;

function TPacketList1.AddPacket(seq:cardinal;buf:PChar;Len:cardinal): boolean;
var i,k:integer;
begin
  result:=false;
  PacketBuf.Write(seq,buf,Len);
  k:=-1;
  for i:=0 to High(Packets) do
  begin
    if Packets[i].seq=seq then
    begin
     assert(false,'Add Packet:Packet exists');
     exit;
    end;
    if (k=-1) and (Packets[i].Len=0) then k:=i;
  end;
  if k=-1 then
  begin
    k:=High(Packets)+1;
    SetLength(Packets, k+1);
  end;
  Packets[k].seq:=seq;
  Packets[k].len:=len;
  result:=true;
end;

function TPacketList1.GetPacket(seq:cardinal;var Buf:PChar;var Len:cardinal): boolean;
var i:integer;p:TPacket1;
begin
  Result:=false;
  for i:=0 to High(Packets) do
  begin
    p:=Packets[i];
    if p.Len=0 then continue;
    if (p.seq <= seq) then
      if (p.seq+p.Len > seq) then
      begin
        PacketBuf.Read(seq,buf);
        Len:=p.Len-(seq-p.seq);
        Packets[i].Len:=0;
        Result:=true;
        break;
      end else Packets[i].Len:=0;  //delete packet
  end;
end;

function TPacketList1.Count: integer;
var i:integer;
begin
  result:=0;
  for i:=0 to High(Packets) do
     if Packets[i].Len>0 then inc(result);
end;

procedure TPacketList1.free;
begin
  PacketBuf.Free;
  inherited free;
end;
constructor TConItem.Create(ASrcIp,ADestIp:integer;ASrcPort,ADestPort: word;Owner:TConList);
begin
  inherited create;
  replybuf:=Tbuf.create(40000);
  reqbuf:=Tbuf.create(2000);
  DestIp:=ADestIp;
  SrcIp:=ASrcIp;
  SrcPort:=ASrcPort;
  DestPort:=ADestPort;
  ReqSeqPosition:=0;
  ReplySeqPosition:=0;
  lastTime:=DateTimeToFileDate(Now());
  ConitemNr:=ConitemNrCount;
  inc(ConitemNrCount);
  FOwner:=Owner;
  HTTPContext:=THTTPContext.create(Owner);
  CloseOnSave:=false;
end;

destructor TConItem.free;
begin
  if PacketList1<>nil then PacketList1.Free;
  if replybuf.DataLen>0 then
  begin
    TConlist(FOwner).OnPaMessage('Lost Bytes: '+HTTPContext.FHost+HTTPContext.FFileName+' Len: '+
    inttostr(replybuf.DataLen)+' Itemnr '+inttostr(ConitemNr)+' Port '+inttostr(SwapWord(@SrcPort)),1);
  end;
  replybuf.free;
  reqbuf.free;
  HTTPContext.free;
end;

function TConItem.onPacket(dir:Integer;IPheader:PIP_header;TCPheader:PTCP_header;TCPPayload:PChar;PayloadLen:cardinal):boolean;
var seq,Len,x:Cardinal; P,SavedPacketBuf:PChar; //first:Boolean;
begin
  result:=false;
  if (TCPheader.flags and TH_FIN)>0 then  CloseOnSave:=true;
  lastTime:=DateTimeToFileDate(Now());
  seq:=SwapDoubleWord(@TCPheader.sequence);
  if PayloadLen>0 then
  if dir > 0 then
  begin
    if ReqSeqPosition=0 then ReqSeqPosition:=seq;
    if not HTTPContext.FHasFoundGet then
      P:=HTTPContext.onRequestStream(TCPPayload,PayloadLen,replybuf) else P:=nil;
    if ReqSeqPosition=seq then
    begin
      if (TCPheader.flags and TH_FIN)>0 then result:=true;
      if P<>nil then  reqbuf.Add(P,integer(PayloadLen)-(P-TCPPayload))
                else reqbuf.Add(TCPPayload,PayloadLen);
      ReqSeqPosition:=ReqSeqPosition + PayloadLen;
    end;
  end else
  begin
    if ReplySeqPosition=0 then begin
     ReplySeqPosition:=seq;
    // first:=true;
    end; //else first:=false;
    if ReplySeqPosition=seq then
    begin
      if (TCPheader.flags and TH_FIN)>0 then result:=true;
      P:=HTTPContext.onReplyData(TCPPayload,PayloadLen,replybuf);
      if P<>nil then replybuf.Add(P,integer(PayloadLen)-(P-TCPPayload));
      ReplySeqPosition:=ReplySeqPosition + PayloadLen;
      if (p=nil) and HTTPContext.FHasFoundGet and not HTTPContext.FHasFoundHTTPReply then
      begin  //Header is late > store packet
        if PacketList1=nil then PacketList1:=TPacketList1.Create;
        PacketList1.AddPacket(seq,TCPPayload,PayloadLen);
        ReplySeqPosition:=0;
      end else
      if (PacketList1<>nil) then   //get all saved packets
        while PacketList1.GetPacket(ReplySeqPosition,SavedPacketBuf,Len) do
        begin
          P:=HTTPContext.onReplyData(SavedPacketBuf,Len,replybuf);
          if p<>nil then replybuf.Add(P,integer(Len)-(P-SavedPacketBuf));
          ReplySeqPosition:=ReplySeqPosition + Len;
        end;
    end else
    begin
      if seq > ReplySeqPosition then
      begin
        if PacketList1=nil then PacketList1:=TPacketList1.Create;
        PacketList1.AddPacket(seq,TCPPayload,PayloadLen);
      end;
      if seq < ReplySeqPosition then
      begin
        if (seq +PayloadLen)> ReplySeqPosition then
        begin
 //        assert(false,'error seq');
          TConlist(FOwner).OnPaMessage('<<<<<<<<<<<<< '+HTTPContext.FHost+HTTPContext.FFileName +(Addr2String(IPheader.source_addr))+
          ' Port:'+inttostr(SwapWord(@TCPheader.source_port))+' > '+
          (Addr2String(IPheader.dest_addr))+' Port:'+inttostr(SwapWord(@TCPheader.dest_port))+
          ' Seq:'+inttostr(seq)+' > SeqPos:'+inttostr(ReplySeqPosition)+
          ' ws: '+inttostr(SwapWord(@TCPheader.tcp_window_size))+' Len= '+inttostr(PayloadLen),2);

          Len:=(seq +PayloadLen)-ReplySeqPosition;  // get needed part of payload  only
          TCPPayload:=TCPPayload+ReplySeqPosition-seq;
          if (TCPheader.flags and TH_FIN)>0 then result:=true;
          P:=HTTPContext.onReplyData(TCPPayload,Len,replybuf);
          if P<>nil then replybuf.Add(P,integer(Len)-(P-TCPPayload));
          ReplySeqPosition:=ReplySeqPosition + Len;
        end;
     end;
   end;
 {   if first and not HTTPContext.FHasFoundHTTPReply and HTTPContext.FHasFoundGet then
      TConlist(FOwner).OnPaMessage('<<<<<<<<<<<<< '+HTTPContext.FHost+HTTPContext.FFileName +(Addr2String(IPheader.source_addr))+
      ' Port:'+inttostr(SwapWord(@TCPheader.source_port))+' > '+
      (Addr2String(IPheader.dest_addr))+' Port:'+inttostr(SwapWord(@TCPheader.dest_port))+
      ' Seq:'+inttostr(seq)+' > SeqPos:'+inttostr(ReplySeqPosition)+
      ' ws: '+inttostr(SwapWord(@TCPheader.tcp_window_size))+' Len= '+inttostr(PayloadLen),2);
   first:=first; }
    if  (PacketList1<>nil) and (PacketList1.Count>0) then result:=false;//dont stop wait for late packets
 {   if  (PacketList1<>nil) then
    begin
      result:=false;//dont stop wait for late packets
      if pos('sb7-040805-SQUID' ,HTTPContext.ffilename) >0 then
        p:=p;
 }
  end;
  if  HTTPContext.FDone then
  begin
    HTTPContext.WriteFile(replybuf);
    if PacketList1<>nil then
    begin
      PacketList1.Free;
      PacketList1:=nil;
    end;
    if CloseOnSave then result:=true;
  end;
end;
function  TConlist.ExchangeBuffer(const Host,Filename:String;Range:Cardinal;var Buffer:Tbuf):boolean;
var i:integer; Buf:Tbuf;
begin
  for i := 0 to (Count - 1) do
  begin
    if TConItem(Items[i]).HTTPContext.FFileName=Filename then
    if TConItem(Items[i]).HTTPContext.FHost=Host then
    if TConItem(Items[i]).replybuf<>Buffer then
    if TConItem(Items[i]).replybuf.DataLen>=Range then
    break;
  end;
  if i<Count then
  begin
    Buf:=TConItem(Items[i]).replybuf;
    TConItem(Items[i]).replybuf:=Buffer;
    Buffer:=buf;
    Result:=true;
  end else Result:=false;
end;
procedure TConlist.Free;
begin
  while Count>0 do
  begin
    TConItem(Items[0]).Free;
    Delete(0);
  end;
  inherited;
end;
procedure TConlist.OnPaMessage(const msg:String;const Info:Integer);
begin
  if Assigned(OnPacketMessage) then OnPacketMessage(msg,Info);
end;
procedure TConlist.OnFileSave(var Filename:String;Host:String;Len:Integer);
begin
   if Assigned(FOnSaveFile) then FOnSaveFile(Filename, Host, Len);
end;
procedure TConlist.OnErrorMsg(const msg:String);
begin
   if Assigned(FOnError) then FOnError(msg);
end;

end.

