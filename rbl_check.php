<?php
                                // Download this file and type: php ./rbl_check.php from the command line to run the script.
$ips = [                        // List of IP addresses to check below: Put all the Mail server addresses you want to check here. Format '127.0.0.1',
    '127.0.0.1',
    '127.0.0.2',
];                              // End List of IP addresses to check.

$showprogress = 1;              // Set to 1 to show the progress report or 0 to silence and just show final results (recommended). Format 1; or 0;

$rbls = [                       // Black lists to check below: Format 'type.black_list.tld',
    'b.barracudacentral.org',
    'cbl.abuseat.org',
    'http.dnsbl.sorbs.net',
    'misc.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'web.dnsbl.sorbs.net',
    'dnsbl-1.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'sbl.spamhaus.org',
    'zen.spamhaus.org',
    'psbl.surriel.com',
    'dnsbl.njabl.org',
    'rbl.spamlab.com',
    'noptr.spamrats.com',
    'cbl.anti-spam.org.cn',
    'dnsbl.inps.de',
    'httpbl.abuse.ch',
    'korea.services.net',
    'virus.rbl.jp',
    'wormrbl.imp.ch',
    'rbl.suresupport.com',
    'ips.backscatterer.org',
    'opm.tornevall.org',
    'multi.surbl.org',
    'tor.dan.me.uk',
    'relays.mail-abuse.org',
    'rbl-plus.mail-abuse.org',
    'access.redhawk.org',
    'rbl.interserver.net',
    'bogons.cymru.com',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'smtp.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'zombie.dnsbl.sorbs.net',
    'dnsbl-2.uceprotect.net',
    'pbl.spamhaus.org',
    'xbl.spamhaus.org',
    'bl.spamcannibal.org',
    'ubl.unsubscore.com',
    'combined.njabl.org',
    'dyna.spamrats.com',
    'spam.spamrats.com',
    'cdl.anti-spam.org.cn',
    'drone.abuse.ch',
    'dul.ru',
    'short.rbl.jp',
    'spamrbl.imp.ch',
    'virbl.bit.nl',
    'dsn.rfc-ignorant.org',
    'dsn.rfc-ignorant.org',
    'netblock.pedantic.org',
    'ix.dnsbl.manitu.net',
    'rbl.efnetrbl.org',
    'blackholes.mail-abuse.org',
    'dnsbl.dronebl.org',
    'db.wpbl.info',
    'query.senderbase.org',
    'bl.emailbasura.org',
    'combined.rbl.msrbl.net',
//  'multi.uribl.com',          // Will always give back 127.0.0.1 on a negative and 127.0.0.2 on a positive. This script is currently not able to decode at that level.
//  'black.uribl.com',          // Will always give back 127.0.0.1 on a negative and 127.0.0.2 on a positive. This script is currently not able to decode at that level.
    'cblless.anti-spam.org.cn',
    'cblplus.anti-spam.org.cn',
    'blackholes.five-ten-sg.com',
    'sorbs.dnsbl.net.au',
    'rmst.dnsbl.net.au',
    'dnsbl.kempt.net',
    'blacklist.woody.ch',
    'rot.blackhole.cantv.net',
    'virus.rbl.msrbl.net',
    'phishing.rbl.msrbl.net',
    'images.rbl.msrbl.net',
    'spam.rbl.msrbl.net',
    'spamlist.or.kr',
    'dnsbl.abuse.ch',
    'bl.deadbeef.com',
    'ricn.dnsbl.net.au',
    'forbidden.icm.edu.pl',
    'probes.dnsbl.net.au',
    'ubl.lashback.com',
    'ksi.dnsbl.net.au',
    'uribl.swinog.ch',
    'bsb.spamlookup.net',
    'dob.sibl.support-intelligence.net',
    'url.rbl.jp',
    'dyndns.rbl.jp',
    'omrs.dnsbl.net.au',
    'osrs.dnsbl.net.au',
    'orvedb.aupads.org',
    'relays.nether.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'dialups.mail-abuse.org',
    'rdts.dnsbl.net.au',
    'duinv.aupads.org',
    'dynablock.sorbs.net',
    'residential.block.transip.nl',
    'dynip.rothen.com',
    'dul.blackhole.cantv.net',
    'mail.people.it',
    'blacklist.sci.kun.nl',
    'all.spamblock.unit.liu.se',
    'spamguard.leadmon.net',
    'csi.cloudmark.com',
];                                                                                      // End black lists to check.

$rbl_count = count($rbls);                                                              // Adds the total number of black lists to check for result reporting.

foreach ($ips as $ip){                                                                  // Begin the RBL checking and reporting.
    $rev = join('.', array_reverse(explode('.', trim($ip))));                           // Format the IP address for the DNS querry.
    $i = 1;                                                                             // Initialize the progress report counter.
    $listed_rbls = [];                                                                  // Initialize the RBL Report Array.
    foreach ($rbls as $rbl){                                                            // Check each IP against the RBL list.
        if ($showprogress) printf('Checking %s, %d of %d... ', $rbl, $i, $rbl_count);   // Progress report line start.
        $lookup = sprintf('%s.%s', $rev, $rbl.'.');                                     // Format the DNS querry.
        $listed = gethostbyname($lookup) !== $lookup;                                   // Perform DNS lookup and return true if DNS querry has a return value.
        if ($showprogress) printf('[%s]%s', $listed ? 'LISTED' : 'OK', PHP_EOL);        // Progress report line end.
        if ($listed) $listed_rbls[] = $rbl;                                             // Add each RBL to final report if there is a match.
        $i++;                                                                           // Advance the progress report Counter.
    }                                                                                   // End the RBL checking and reporting.
    printf('%s is listed on %d of %d known blacklists%s', $ip, count($listed_rbls), $rbl_count, PHP_EOL);   // Report number of RBL matches on the final report.
    if ( ! empty($listed_rbls) ) printf('%s is listed on %s%s', $ip, join(', ', $listed_rbls), PHP_EOL);    // Report RBL's that had a match on the final report.
}                                                                                       // The End. Hope you enjoy the script.............
?>