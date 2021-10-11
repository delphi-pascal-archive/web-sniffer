{
    websniffer - PcapNet.pas (Ver1.1)(HTTP connection analysis)
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
unit PcapNet;

interface
uses   Windows;
const TH_SYN  =	2;
      TH_FIN  = 1;
      CONNECTION_TIMEOUT = 25 ;  // seconds
type

   TErrBuf=array[0..256] of char;

   Psockaddr = ^Tsockaddr;
   Tsockaddr = packed record
  	   safamily: word ;                  // address family
	   sadata: array[1..14] of char;     // up to 14 bytes of direct address
   end;

   Pcap_addr = ^Tcap_addr;
   Tcap_addr = packed record
           next: pcap_addr ;
	   addr: Psockaddr;      // address
	   netmask: Psockaddr;	 // netmask for that address
	   broadaddr: Psockaddr; // broadcast address for that address
	   dstaddr:Psockaddr;    // P2P destination address for that address
   end;

  Pcap_if = ^Tcap_if;
  Tcap_if = packed record
          next:pcap_if;
          name: LPSTR;           // name to hand to "pcap_open_live()"
          description: LPSTR;    // textual description of interface, or NULL
          addresses:Pcap_addr;
          bpf_u_int32:Cardinal;  // PCAP_IF_ interface flags
  end;
 // Callback function invoked by libpcap for every incoming packet
  packet_handler_procedure= procedure(param,header,pkt_data:Pointer);

type
  PTCP_header= ^TTCP_header;
  TTCP_header= packed record
                    source_port: Word; // endian
                    dest_port: Word; // endian
                    sequence: dWord;
                    tcp_acknowledgement: dWord;
                    tcp_reserved_and_header_size: Byte;
                    flags: Byte;
                    tcp_window_size: Word;
                    tcp_checksum: Word;
                    tcp_last_urgent_byte: Word;
                                   // -- variable size
                    tcp_data: array[0..0] of Byte;
                  end;

  TIPaddress= array[0..3] of BYTE;

  PIP_header= ^TIP_header;
  TIP_header= packed record  // 20 bytes+ data
                    version_and_header_length: Byte;
                    type_of_service: Byte;
                    total_len: Word;
                     // -- identification of a datagram
                    datagram_identification: Word;
                    flag_and_offset: Word;
                    time_to_live: Byte;
                    proto: Byte;
                    check_sum: Word;
                    source_addr: TIPaddress;
                    dest_addr: TIPaddress;
                      // -- variable size
                    ip_data: array[0..0] of Byte;
                  end;

  Ptimeval = ^Ttimeval;
  Ttimeval = packed record
    tv_sec:integer;             // seconds
    tv_usec: integer;           // and microseconds
  end;

  Pcap_pkthdr = ^Tpcap_pkthdr;
  Tpcap_pkthdr = packed record
    ts:Ttimeval;             // time stamp
    caplen: integer;         // length of portion present
    len: integer;            // length this packet (off wire)
  end;
  Tpcap_findalldevs = function (x:pcap_if; lpszName: LPSTR): Cardinal; cdecl;
  Tpcap_freealldevs = procedure (x:pcap_if); cdecl;
  Tpcap_open_live = function (name:LPSTR; portion,promisc,timeout:Integer;errbuf:LPSTR): Pointer; cdecl; 
  Tpcap_loop = function (adhandle:Pointer; i:integer;packet_handler_procedure:Pointer; s:Lpstr): Cardinal; cdecl;
  Tpcap_breakloop = procedure (adhandle:Pointer);cdecl;
  THandle = Integer;
  function URLDecode(Sp: Pchar;Len:integer): String;
  function PChar2String(P:PChar;len:Integer):String;
  function Addr2String(adr:TIPaddress):String;
  function SwapWord(px: PChar): Word;
  function SwapDoubleWord(px: PChar): Cardinal;
  function PosEx(const SubStr, S: string; Offset: Cardinal = 1): Integer;
  function SizeOfFile(const FileName: String): integer;

var ConitemNrCount:integer =0;
    Handlewpcap:THandle;
    pcap_findalldevs: Tpcap_findalldevs;
    pcap_freealldevs: Tpcap_freealldevs;
    pcap_open_live: Tpcap_open_live;
    pcap_loop: Tpcap_loop;
    pcap_breakloop: Tpcap_breakloop;

implementation
uses sysutils;
function PChar2String(P:PChar;len:Integer):String;
var i:Integer;
begin
 SetLength(Result,len);
 for i:=1 to len do begin
  result[i]:=P^;
  p:=p+1;
 end;
end;
function Addr2String(adr:TIPaddress):String;
begin
 result:=inttostr(adr[0])+'.'+inttostr(adr[1])+'.'+inttostr(adr[2])+'.'+inttostr(adr[3]);
end;
function SwapWord(px: PChar): Word;
begin
  Result:= (word(px^) shl 8) or (word((px+1)^));
end;

function SwapDoubleWord(px: PChar): Cardinal;
begin
 Result:= (Integer(px^) shl 24) or
          (Integer((px+ 1)^) shl 16) or
          (Integer((px+ 2)^) shl 8) or
          (Integer((px+ 3)^));
end;
function HTTPDecode(const AStr: String): String;
var
  Sp, Rp, Cp: PChar;
  S: String;
begin
  SetLength(Result, Length(AStr));
  Sp := PChar(AStr);
  Rp := PChar(Result);
  Cp := Sp;
  try
    while Sp^ <> #0 do
    begin
      case Sp^ of
        '+': Rp^ := ' ';
        '%': begin
               // Look for an escaped % (%%) or %<hex> encoded character
               Inc(Sp);
               if Sp^ = '%' then
                 Rp^ := '%'
               else
               begin
                 Cp := Sp;
                 Inc(Sp);
                 if (Cp^ <> #0) and (Sp^ <> #0) then
                 begin
                   S := '$' + Cp^ + Sp^;
                   Rp^ := Chr(StrToInt(S));
                 end
                 else
                   raise EConvertError.CreateFmt('sErrorDecodingURLText', [Cp - PChar(AStr)]);
               end;
             end;
      else
        Rp^ := Sp^;
      end;
      Inc(Rp);
      Inc(Sp);
    end;
  except
    on E:EConvertError do
      raise EConvertError.CreateFmt('sInvalidURLEncodedChar',
        ['%' + Cp^ + Sp^, Cp - PChar(AStr)])
  end;
  SetLength(Result, Rp - PChar(Result));
end;
function URLDecode(Sp: Pchar;Len:integer): String;
var
  Rp, Cp, Ep: PChar;
  S: String; i:integer;
begin
  SetLength(Result, Len);
  Rp := PChar(Result);
  Cp := Sp; Ep := Sp+Len;
  try
    while Sp < EP do
    begin
      case Sp^ of
        '+': Rp^ := ' ';
        '%': begin
               // Look for an escaped % (%%) or %<hex> encoded character
               Inc(Sp);
               if Sp^ = '%' then
                 Rp^ := '%'
               else
               begin
                 Cp := Sp;
                 Inc(Sp);
                 if (Cp^ <> #0) and (Sp^ <> #0) then
                 begin
                   S := '$' + Cp^ + Sp^;
                   if TryStrToInt(S,i) and (i<256) then
                    Rp^ := Chr(StrToInt(S)) else
                    Rp^ := Sp^;
                 end
                 else
                   raise EConvertError.CreateFmt('sErrorDecodingURLText', [Cp - Sp]);
               end;
             end;
      else
        Rp^ := Sp^;
      end;
      Inc(Rp);
      Inc(Sp);
    end;
  except
    on E:EConvertError do
      raise EConvertError.CreateFmt('sInvalidURLEncodedChar',
        ['%' + Cp^ + Sp^, Cp - Sp])
  end;
  SetLength(Result, Rp - PChar(Result));
end;
function PosEx(const SubStr, S: string; Offset: Cardinal = 1): Integer;
var
  I,X: Integer;
  Len, LenSubStr: Integer;
begin
  if Offset = 1 then
    Result := Pos(SubStr, S)
  else
  begin
    I := Offset;
    LenSubStr := Length(SubStr);
    Len := Length(S) - LenSubStr + 1;
    while I <= Len do
    begin
      if S[I] = SubStr[1] then
      begin
        X := 1;
        while (X < LenSubStr) and (S[I + X] = SubStr[X + 1]) do
          Inc(X);
        if (X = LenSubStr) then
        begin
          Result := I;
          exit;
        end;
      end;
      Inc(I);
    end;
    Result := 0;
  end;
end;
function SizeOfFile(const FileName: String): integer;
var  f: file;
begin
  result:=0;
  if not FileExists(FileName) then exit;
  AssignFile(f, FileName);
  FileMode := 0;
  Reset(f, 1);
  result:=FileSize(f);
  CloseFile(f);
end;
Initialization
  Handlewpcap := LoadLibrary('wpcap.dll');
  if Handlewpcap <> 0 then
  begin
    @pcap_findalldevs := GetProcAddress(Handlewpcap, 'pcap_findalldevs');
    @pcap_freealldevs := GetProcAddress(Handlewpcap, 'pcap_freealldevs');
    @pcap_open_live:= GetProcAddress(Handlewpcap, 'pcap_open_live');
    @pcap_loop:= GetProcAddress(Handlewpcap, 'pcap_loop');
    @pcap_breakloop:= GetProcAddress(Handlewpcap, 'pcap_breakloop');
    if (@pcap_findalldevs = nil) or (@pcap_freealldevs = nil) or (@pcap_open_live = nil)
     or (@pcap_loop = nil) or (@pcap_breakloop = nil)  then
    begin
      FreeLibrary(Handlewpcap);
      Handlewpcap:=0;
    end;
  end;

finalization
    FreeLibrary(Handlewpcap);
end.
