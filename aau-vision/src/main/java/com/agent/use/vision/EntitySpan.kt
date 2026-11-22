package com.agent.use.vision

/**
 * Entity classes produced by the on-device NER model. `Address` is a written address
 * ("上海市浦东新区世纪大道100号"), the oral variants are spoken forms ("望京那个soho"),
 * and `AdministrativeDivision` covers province/city/district names on their own.
 */
enum class EntityType {
    Person,
    Phone,
    Address,
    OralAddress,
    OralWideAddress,
    AdministrativeDivision,
    Company,
    Organization,
    Government,
    School,
    Healthcare,
    Restaurant,
    Hotel,
    Supermarket,
    Entertainment,
    Spot,
    OfficeBuilding,
    Bank,
    BankCard,
    ExpressNumber,
    FlightNumber,
    TrainNumber,
    SubwayStation,
    BusStation,
    AirportTrain,
    OilElectric,
    OtherAddress,

    /** A label this build does not know. Only when a newer model ships new classes. */
    Other,
}

/** Half-open character range [start, end) into the text passed to [AauEntityExtractor.extract]. */
data class EntitySpan(val type: EntityType, val start: Int, val end: Int, val text: String)
