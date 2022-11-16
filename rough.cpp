#include <string>
#include <iostream>
#include "crn/utils.h"
#include "crn/keys.h"
#include <cryptopp/modarith.h>
#include <cryptopp/osrng.h>
#include <cassert>
#include "crn/math/line.h"

int main(int argc, char** argv){
    // CryptoPP::Integer x1("59155865408868259425557571612471620428297988408165845346132791388203026665780027334884289790496698975366550859751679098576474914656477108493456088740714638392460074168696957786644452257687431017811952658833178670113578592426217762888790213090753444458649558440508900270736330461377938922007295905864081619510");
    // CryptoPP::Integer x2("49171792422277804394667843819141913847322600280665849545551047558807915445878344561751437746234579327835202256618036154257179856084340066038426734660095847831493104314549773675359068536806511510632346258713769955285829778738241140307603773114365677760401574036178965775449693351366955171071039150496892512626");
    // CryptoPP::Integer y1("15532588564541259482922018944097853897300168981677954188716754703307497158337714880433137687641278802841087340039578684036658054493398074873834397457078926775924304480658287770519079275439081927738422285768406410397661454394363161024640626036869355676305517960711933863623200507534787097131264154704514178528");
    // CryptoPP::Integer y2("18681104435936101884448227316030762542107116083698320896806859540547443331269148757807169307897834606930640490118708410979463001754418260497415780748530755543566898480965940648878220684347582565134185256730690865433076765778856737642958127745233063853975442413445206113883902055488910897572165540719794965920");
    // CryptoPP::Integer p ("171320888899847002522538286010717970050712035465289873249959090208041304926005539317533010051124825774622387763181990139801020807777709472681854339326432257665967930555817418179389068496976851304848858267411231278762526840486673505596715269737069851957355166043141770807768677357720176332759237252035377645721");

    // std::cout << "x1: " << x1 << std::endl << "x2: " << x2 << std::endl << "y1: " << y1 << std::endl << "y2: " << y2 << std::endl;
    // std::cout << std::endl;
    //
    // assert(x1 < p);
    // assert(x2 < p);
    // assert(y1 < p);
    // assert(y2 < p);
    //
    // {
    //     std::cout << "Group: " << std::endl;
    //     CryptoPP::ModularArithmetic Gp(p);
    //
    //     CryptoPP::Integer dx  = Gp.Subtract(x2, x1), dy = Gp.Subtract(y2, y1), mdy = Gp.Subtract(y1, y2);
    //     CryptoPP::Integer c   = Gp.Subtract(Gp.Multiply(x2, y1), Gp.Multiply(y2, x1));
    //
    //     std::cout << "Gp.Multiply(x2, y1): " << Gp.Multiply(x2, y1) << std::endl
    //               << "Gp.Multiply(y2, x1): " << Gp.Multiply(y2, x1) << std::endl
    //               << "c: " << c << std::endl
    //               << "Gp.Multiply(x2, y1) - Gp.Multiply(y2, x1): " << (Gp.Multiply(x2, y1) - Gp.Multiply(y2, x1)) << std::endl;
    //
    //     CryptoPP::Integer a = mdy, b = dx;
    //
    //     std::cout << Gp.Divide(Gp.Subtract(c, Gp.Multiply(x1, a)), b) << std::endl;
    //     std::cout << Gp.Add( Gp.Multiply(a, x1), Gp.Multiply(b, y1) ) << " " << c << std::endl;
    // }
    //
    // {
    //     std::cout << "Not in Group: " << std::endl;
    //     CryptoPP::Integer dx = x2 - x1, dy = y2 - y1, mdy = y1 - y2;
    //     CryptoPP::Integer c  = (x2 * y1) - (y2 * x1);
    //
    //     CryptoPP::Integer a = mdy, b = dx;
    //
    //     std::cout << (c - (x1 * a)) / b << std::endl;
    //
    // }


    // CryptoPP::Integer a("-24");
    // std::string hex = crn::utils::eHex(a);
    // CryptoPP::Integer b = crn::utils::dHex(hex, true);
    //
    // std::cout << hex << std::endl << b << std::endl;

    // CryptoPP::AutoSeededRandomPool rng;
    //
    // crn::free_coordinates p1{5, -7}, p2{8, -12};
    // auto line = crn::linear_diophantine::interpolate(p1, p2);
    //
    // auto r1 = line.random(rng, 50);
    // auto r2 = line.random(rng, 50);
    //
    // std::cout << line << std::endl;
    // std::cout << r1 << std::endl;
    // std::cout << crn::linear_diophantine::interpolate(p1, r1) << std::endl;
    // std::cout << r2 << std::endl;
    //
    // assert(crn::linear_diophantine::interpolate(p1, r1) == line);
    // assert(crn::linear_diophantine::interpolate(p2, r1) == line);
    // assert(crn::linear_diophantine::interpolate(p1, r2) == line);
    // assert(crn::linear_diophantine::interpolate(p2, r2) == line);
    // assert(crn::linear_diophantine::interpolate(r2, r1) == line);

//    CryptoPP::Integer s = -17, d = -3;
//    CryptoPP::Integer min = (2-s) / d;
//    CryptoPP::Integer max = (100-s) / d;
//    std::cout << min << std::endl;
//    std::cout << max << std::endl;

//    CryptoPP::AutoSeededRandomPool rng;
//    CryptoPP::Integer r(rng, std::min(min, max), std::max(min, max));
//    std::cout << (s + (r * d)) << std::endl;

    CryptoPP::Integer input("186633539891002931657903750944036618999121140963084441002216962744063819191747778554251739081222280194591114477120837017347391135685014884998818270812356287863278733776657004536784711864987844059518625183113291316963478075992615428701873885603882558519838236649371224041513368881332877284661694696234762507103618674240516886679599578991724726024224533261887533319966030600727820886568027737247883559933896208827396126093239144545827918042186634278635947001842854676887680983235599222536135945517403491220345489274779478737751808274681116360");
    std::string shex = crn::utils::eHex(input, CryptoPP::Integer::SIGNED);
    std::string uhex = crn::utils::eHex(input, CryptoPP::Integer::UNSIGNED);
    std::cout << shex << std::endl << uhex << std::endl;
    std::cout << crn::utils::dHex(uhex, CryptoPP::Integer::SIGNED) << std::endl;
    // std::cout << crn::utils::dHex(hex, true) << std::endl;


}
