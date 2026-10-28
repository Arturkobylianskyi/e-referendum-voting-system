import java.time.LocalDate;
import java.time.Period;

public class PeselValidator {
    private static final int[] WEIGHTS = {1, 3, 7, 9, 1, 3, 7, 9, 1, 3};

    private PeselValidator(){};

    public static boolean isValidChecksum(String pesel){
        if(pesel == null || !pesel.matches("\\d{11}")){
            return false;
        }

        int sum = 0;
        for(int i = 0; i < 10; i++){
            int num = Character.getNumericValue(pesel.charAt(i));
            sum += num * WEIGHTS[i];
        }

        int controlDigit = (10 - (sum % 10)) % 10;
        int lastDigit = Character.getNumericValue(pesel.charAt(10));

        return controlDigit == lastDigit;
    }

    public static LocalDate extractBirthDate(String pesel){
        if(!isValidChecksum(pesel)){
            throw new IllegalArgumentException("Invalid pesel: " + pesel);
        }

        int year = Integer.parseInt(pesel.substring(0, 2));
        int month = Integer.parseInt(pesel.substring(2, 4));
        int day = Integer.parseInt(pesel.substring(4, 6));

        if(month >= 1 && month <= 12){
            year += 1900;
        }
        else if(month >= 21 && month <= 32){
            year += 2000;
            month -= 20;
        }
        else if(month >= 81 && month <= 92){
            year += 1800;
            month -= 80;
        }
        else{
            throw new IllegalArgumentException("Incorrect month in pesel");
        }

        return LocalDate.of(year, month, day);
    }

    public static boolean isAdultVoter(String pesel, LocalDate electionDate){
        if(!isValidChecksum(pesel)){
            return false;
        }

        LocalDate birthDate = extractBirthDate(pesel);
        return Period.between(birthDate, electionDate).getYears() >= 18;

    }

}
