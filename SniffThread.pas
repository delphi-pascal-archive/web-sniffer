{
    websniffer - SniffThread.pas (Ver1.1) (HTTP connection analysis)
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
unit SniffThread;

interface

uses
  Classes,PcapNet,conitem;

type
  TSniffThread = class(TThread)
  private
    Fadhandle:Pointer;
  protected
    procedure Execute; override;
  public
    procedure Run(adhandle:Pointer);
    procedure Stop;
  end;

var ConList:TConList;
    fs : TFileStream;
    SniffThread1:TSniffThread;
    LogFileName:String;

implementation

uses StrUtils,sysutils,MainForm;

procedure  HandleTCP(IPheader:PIP_header;TCPheader:PTCP_header;TCPPayload:PChar;PayloadLen:cardinal);
var ConItem:TConItem;i,n,dir:Integer;
begin
    n:=DateTimeToFileDate(Now());
    for i := 0 to (ConList.Count - 1) do
    begin
      with TConItem(ConList.Items[i]) do begin
        if (n-lastTime) > CONNECTION_TIMEOUT then
        begin
          form1.StatusBar.Panels[1].Text:='timeout';
          TConItem(ConList.Items[i]).Free;
          ConList.Delete(i);
          form1.StatusBar.Panels[0].Text:='Ports:'+inttostr(ConList.Count);
          break;
        end;
      end;
    end;
    for i := 0 to (ConList.Count - 1) do
    begin
     with TConItem(ConList.Items[i]) do begin
      dir:=0;
      if (TCPheader.source_port=SrcPort) and  (TCPheader.dest_port=DestPort) and
         (integer(IPheader.dest_addr)=DestIp) and (integer(IPheader.source_addr)=SrcIp) then
        dir:=1 else
      if (TCPheader.source_port=DestPort) and  (TCPheader.dest_port= SrcPort) and
         (integer(IPheader.dest_addr)=SrcIp) and (integer(IPheader.source_addr)=DestIp ) then
        dir:=-1;
      if dir<>0 then
      begin
         TConItem(ConList.Items[i]).lastTime:=DateTimeToFileDate(Now());
         if onPacket(dir,IPheader,TCPheader,TCPPayload,payloadLen) then
          begin
            TConItem(ConList.Items[i]).Free;
            ConList.Delete(i);
            form1.StatusBar.Panels[0].Text:='Ports:'+inttostr(ConList.Count);
          end;
          exit;
       end;
     end;
    end;
    if TCPheader.flags = TH_SYN then
    begin
      ConItem:=TConItem.create(integer(IPheader.source_addr),integer(IPheader.dest_addr),
               TCPheader.source_port,TCPheader.dest_port,ConList);
      ConList.Add(Pointer(ConItem));
      form1.StatusBar.Panels[0].Text:='Ports:'+inttostr(ConList.Count);
    end;
end;

procedure packet_handler(param:Pointer;header:pcap_pkthdr;pkt_data:Pointer); cdecl;
var IpLen,PktLen,thOffs:integer; IPheader:PIP_header;
  IHL:byte; version:byte;TCPheader:PTCP_header;TCPPayload:PChar;
const  ETHLEN:integer = 14; // length of ethernet packet headers
begin
  PktLen:=header.caplen-ETHLEN;
  IPheader:=PIP_header(PChar(pkt_data)+ETHLEN);
  IpLen:=SwapWord(@IPheader.total_len);
  ihl  :=IPheader.version_and_header_length and $0f;
  version :=IPheader.version_and_header_length shr 4;
  if (PktLen < IpLen) then exit; // incomplete packet
  PktLen:= IpLen - IHL * 4;
  if (version <> 4) or (IHL < 5) or ( PktLen <= 0) then exit; // invalid IP header
  if (IPheader.proto <> 6) then exit; // not TCP
  TCPheader:=PTCP_header(PChar(IPheader) + IHL*4);
  thOffs:=TCPheader.tcp_reserved_and_header_size shr 4;
  PktLen :=PktLen-thOffs*4;
  if (thOffs < 5 )or( PktLen < 0) then exit;
  TCPPayload := PChar(TCPheader) + thOffs*4;
  if Assigned(fs) then
  begin
    fs.Write(PChar(IPheader)^,Sizeof(TIP_header));
    fs.WriteBuffer(TCPheader^,Sizeof(TTCP_header));
    fs.WriteBuffer(PktLen,4);
    fs.WriteBuffer(TCPPayload^,PktLen);
  end;
  HandleTCP(IPheader,TCPheader,TCPPayload,PktLen);
end;
{ SniffThread }
procedure TSniffThread.Run(adhandle:Pointer);
begin
  Fadhandle:=adhandle;
end;
procedure TSniffThread.stop;
begin
  pcap_breakloop(Fadhandle);
end;

procedure TSniffThread.Execute;
var i:integer;
begin
  if MainForm.Form1.CheckBoxLog.Checked then
  begin
    for i:=1 to 1000 do
    begin
      LogFileName:='WebSniff'+inttostr(i)+'.log';
      if SizeOfFile(LogFileName)=0 then break;
    end;
    fs := TFileStream.Create(LogFileName, fmCreate or fmOpenWrite);
  end;
  try
    pcap_loop(Fadhandle, 0, @packet_handler, nil);
  finally
    if assigned(fs) then fs.Free;
    fs:=nil;
    ConList.Free;
  end;
end;

end.
